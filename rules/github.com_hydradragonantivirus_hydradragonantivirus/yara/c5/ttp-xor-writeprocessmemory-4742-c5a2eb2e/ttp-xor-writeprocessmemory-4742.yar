rule TTP_XOR_WriteProcessMemory_4742 {
  strings:
    $key_4742 = { 10 30 [2] 22 12 [2] 24 27 [2] 0a 27 [2] 35 3b }

  condition:
    any of them
}