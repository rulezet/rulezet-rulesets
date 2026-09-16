rule TTP_XOR_WriteProcessMemory_acb9 {
  strings:
    $key_acb9 = { fb cb [2] c9 e9 [2] cf dc [2] e1 dc [2] de c0 }

  condition:
    any of them
}