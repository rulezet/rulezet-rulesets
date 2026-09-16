rule TTP_XOR_WriteProcessMemory_50ea {
  strings:
    $key_50ea = { 07 98 [2] 35 ba [2] 33 8f [2] 1d 8f [2] 22 93 }

  condition:
    any of them
}