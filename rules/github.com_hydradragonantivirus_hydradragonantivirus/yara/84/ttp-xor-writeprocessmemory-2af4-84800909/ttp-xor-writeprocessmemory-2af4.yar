rule TTP_XOR_WriteProcessMemory_2af4 {
  strings:
    $key_2af4 = { 7d 86 [2] 4f a4 [2] 49 91 [2] 67 91 [2] 58 8d }

  condition:
    any of them
}