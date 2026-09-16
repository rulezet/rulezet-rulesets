rule TTP_XOR_WriteProcessMemory_2ae1 {
  strings:
    $key_2ae1 = { 7d 93 [2] 4f b1 [2] 49 84 [2] 67 84 [2] 58 98 }

  condition:
    any of them
}