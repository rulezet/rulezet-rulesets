rule TTP_XOR_WriteProcessMemory_3b94 {
  strings:
    $key_3b94 = { 6c e6 [2] 5e c4 [2] 58 f1 [2] 76 f1 [2] 49 ed }

  condition:
    any of them
}