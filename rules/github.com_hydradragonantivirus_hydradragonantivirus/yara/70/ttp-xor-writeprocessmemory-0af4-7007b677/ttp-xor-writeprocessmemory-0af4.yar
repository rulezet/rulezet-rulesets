rule TTP_XOR_WriteProcessMemory_0af4 {
  strings:
    $key_0af4 = { 5d 86 [2] 6f a4 [2] 69 91 [2] 47 91 [2] 78 8d }

  condition:
    any of them
}