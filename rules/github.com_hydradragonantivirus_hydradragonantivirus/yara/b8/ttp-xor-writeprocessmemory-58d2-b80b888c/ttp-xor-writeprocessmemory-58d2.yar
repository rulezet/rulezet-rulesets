rule TTP_XOR_WriteProcessMemory_58d2 {
  strings:
    $key_58d2 = { 0f a0 [2] 3d 82 [2] 3b b7 [2] 15 b7 [2] 2a ab }

  condition:
    any of them
}