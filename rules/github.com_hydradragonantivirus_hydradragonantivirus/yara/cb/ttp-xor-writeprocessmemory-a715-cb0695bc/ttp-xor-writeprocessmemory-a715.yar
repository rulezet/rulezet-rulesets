rule TTP_XOR_WriteProcessMemory_a715 {
  strings:
    $key_a715 = { f0 67 [2] c2 45 [2] c4 70 [2] ea 70 [2] d5 6c }

  condition:
    any of them
}