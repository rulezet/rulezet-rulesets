rule TTP_XOR_WriteProcessMemory_a759 {
  strings:
    $key_a759 = { f0 2b [2] c2 09 [2] c4 3c [2] ea 3c [2] d5 20 }

  condition:
    any of them
}