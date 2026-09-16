rule TTP_XOR_WriteProcessMemory_5af4 {
  strings:
    $key_5af4 = { 0d 86 [2] 3f a4 [2] 39 91 [2] 17 91 [2] 28 8d }

  condition:
    any of them
}