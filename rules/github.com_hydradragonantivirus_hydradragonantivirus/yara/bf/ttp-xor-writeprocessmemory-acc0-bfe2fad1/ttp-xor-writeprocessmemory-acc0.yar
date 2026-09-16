rule TTP_XOR_WriteProcessMemory_acc0 {
  strings:
    $key_acc0 = { fb b2 [2] c9 90 [2] cf a5 [2] e1 a5 [2] de b9 }

  condition:
    any of them
}