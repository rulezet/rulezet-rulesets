rule TTP_XOR_WriteProcessMemory_e694 {
  strings:
    $key_e694 = { b1 e6 [2] 83 c4 [2] 85 f1 [2] ab f1 [2] 94 ed }

  condition:
    any of them
}