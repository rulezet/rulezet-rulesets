rule TTP_XOR_WriteProcessMemory_acc6 {
  strings:
    $key_acc6 = { fb b4 [2] c9 96 [2] cf a3 [2] e1 a3 [2] de bf }

  condition:
    any of them
}