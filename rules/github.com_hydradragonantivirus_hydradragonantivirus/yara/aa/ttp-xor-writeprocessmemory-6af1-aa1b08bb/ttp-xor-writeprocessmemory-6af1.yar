rule TTP_XOR_WriteProcessMemory_6af1 {
  strings:
    $key_6af1 = { 3d 83 [2] 0f a1 [2] 09 94 [2] 27 94 [2] 18 88 }

  condition:
    any of them
}