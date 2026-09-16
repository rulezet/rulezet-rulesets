rule TTP_XOR_WriteProcessMemory_203d {
  strings:
    $key_203d = { 77 4f [2] 45 6d [2] 43 58 [2] 6d 58 [2] 52 44 }

  condition:
    any of them
}