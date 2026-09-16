rule TTP_XOR_WriteProcessMemory_8036 {
  strings:
    $key_8036 = { d7 44 [2] e5 66 [2] e3 53 [2] cd 53 [2] f2 4f }

  condition:
    any of them
}