rule TTP_XOR_WriteProcessMemory_e629 {
  strings:
    $key_e629 = { b1 5b [2] 83 79 [2] 85 4c [2] ab 4c [2] 94 50 }

  condition:
    any of them
}