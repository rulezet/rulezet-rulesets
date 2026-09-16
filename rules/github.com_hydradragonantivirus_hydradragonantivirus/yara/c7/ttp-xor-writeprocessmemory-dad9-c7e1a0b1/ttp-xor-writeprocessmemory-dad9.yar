rule TTP_XOR_WriteProcessMemory_dad9 {
  strings:
    $key_dad9 = { 8d ab [2] bf 89 [2] b9 bc [2] 97 bc [2] a8 a0 }

  condition:
    any of them
}