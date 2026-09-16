rule TTP_XOR_WriteProcessMemory_acc4 {
  strings:
    $key_acc4 = { fb b6 [2] c9 94 [2] cf a1 [2] e1 a1 [2] de bd }

  condition:
    any of them
}