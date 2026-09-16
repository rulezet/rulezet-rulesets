rule TTP_XOR_WriteProcessMemory_64e3 {
  strings:
    $key_64e3 = { 33 91 [2] 01 b3 [2] 07 86 [2] 29 86 [2] 16 9a }

  condition:
    any of them
}