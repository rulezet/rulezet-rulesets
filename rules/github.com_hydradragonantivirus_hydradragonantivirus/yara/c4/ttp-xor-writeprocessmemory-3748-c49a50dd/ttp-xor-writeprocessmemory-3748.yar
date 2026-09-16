rule TTP_XOR_WriteProcessMemory_3748 {
  strings:
    $key_3748 = { 60 3a [2] 52 18 [2] 54 2d [2] 7a 2d [2] 45 31 }

  condition:
    any of them
}