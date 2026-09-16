rule TTP_XOR_WriteProcessMemory_58d7 {
  strings:
    $key_58d7 = { 0f a5 [2] 3d 87 [2] 3b b2 [2] 15 b2 [2] 2a ae }

  condition:
    any of them
}