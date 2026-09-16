rule TTP_XOR_WriteProcessMemory_58c1 {
  strings:
    $key_58c1 = { 0f b3 [2] 3d 91 [2] 3b a4 [2] 15 a4 [2] 2a b8 }

  condition:
    any of them
}