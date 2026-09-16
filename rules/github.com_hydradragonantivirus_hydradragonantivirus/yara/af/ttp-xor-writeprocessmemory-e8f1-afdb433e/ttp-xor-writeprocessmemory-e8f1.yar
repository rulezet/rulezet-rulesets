rule TTP_XOR_WriteProcessMemory_e8f1 {
  strings:
    $key_e8f1 = { bf 83 [2] 8d a1 [2] 8b 94 [2] a5 94 [2] 9a 88 }

  condition:
    any of them
}