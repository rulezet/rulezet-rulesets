rule TTP_XOR_WriteProcessMemory_4ae3 {
  strings:
    $key_4ae3 = { 1d 91 [2] 2f b3 [2] 29 86 [2] 07 86 [2] 38 9a }

  condition:
    any of them
}