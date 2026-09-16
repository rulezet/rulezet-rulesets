rule TTP_XOR_WriteProcessMemory_fca2 {
  strings:
    $key_fca2 = { ab d0 [2] 99 f2 [2] 9f c7 [2] b1 c7 [2] 8e db }

  condition:
    any of them
}