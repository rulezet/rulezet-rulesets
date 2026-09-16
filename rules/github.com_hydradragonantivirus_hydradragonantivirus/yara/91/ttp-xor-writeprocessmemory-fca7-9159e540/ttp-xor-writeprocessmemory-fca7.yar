rule TTP_XOR_WriteProcessMemory_fca7 {
  strings:
    $key_fca7 = { ab d5 [2] 99 f7 [2] 9f c2 [2] b1 c2 [2] 8e de }

  condition:
    any of them
}