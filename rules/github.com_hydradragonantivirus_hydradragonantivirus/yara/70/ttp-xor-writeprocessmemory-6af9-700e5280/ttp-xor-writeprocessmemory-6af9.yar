rule TTP_XOR_WriteProcessMemory_6af9 {
  strings:
    $key_6af9 = { 3d 8b [2] 0f a9 [2] 09 9c [2] 27 9c [2] 18 80 }

  condition:
    any of them
}