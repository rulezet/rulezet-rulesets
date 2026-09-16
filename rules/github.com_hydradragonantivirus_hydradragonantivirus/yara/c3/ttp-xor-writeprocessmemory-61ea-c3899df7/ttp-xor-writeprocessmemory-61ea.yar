rule TTP_XOR_WriteProcessMemory_61ea {
  strings:
    $key_61ea = { 36 98 [2] 04 ba [2] 02 8f [2] 2c 8f [2] 13 93 }

  condition:
    any of them
}