rule TTP_XOR_WriteProcessMemory_71ea {
  strings:
    $key_71ea = { 26 98 [2] 14 ba [2] 12 8f [2] 3c 8f [2] 03 93 }

  condition:
    any of them
}