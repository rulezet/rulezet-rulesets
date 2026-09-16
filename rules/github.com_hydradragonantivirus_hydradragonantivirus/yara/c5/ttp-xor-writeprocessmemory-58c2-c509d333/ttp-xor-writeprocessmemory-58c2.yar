rule TTP_XOR_WriteProcessMemory_58c2 {
  strings:
    $key_58c2 = { 0f b0 [2] 3d 92 [2] 3b a7 [2] 15 a7 [2] 2a bb }

  condition:
    any of them
}