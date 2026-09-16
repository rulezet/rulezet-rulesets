rule TTP_XOR_WriteProcessMemory_6af4 {
  strings:
    $key_6af4 = { 3d 86 [2] 0f a4 [2] 09 91 [2] 27 91 [2] 18 8d }

  condition:
    any of them
}