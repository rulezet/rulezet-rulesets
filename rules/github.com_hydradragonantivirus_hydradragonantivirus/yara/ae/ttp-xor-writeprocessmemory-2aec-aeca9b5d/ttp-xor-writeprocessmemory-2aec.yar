rule TTP_XOR_WriteProcessMemory_2aec {
  strings:
    $key_2aec = { 7d 9e [2] 4f bc [2] 49 89 [2] 67 89 [2] 58 95 }

  condition:
    any of them
}