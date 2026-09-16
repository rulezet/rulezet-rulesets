rule TTP_XOR_WriteProcessMemory_8056 {
  strings:
    $key_8056 = { d7 24 [2] e5 06 [2] e3 33 [2] cd 33 [2] f2 2f }

  condition:
    any of them
}