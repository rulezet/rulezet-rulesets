rule TTP_XOR_WriteProcessMemory_e6f1 {
  strings:
    $key_e6f1 = { b1 83 [2] 83 a1 [2] 85 94 [2] ab 94 [2] 94 88 }

  condition:
    any of them
}