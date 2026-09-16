rule TTP_XOR_WriteProcessMemory_acc1 {
  strings:
    $key_acc1 = { fb b3 [2] c9 91 [2] cf a4 [2] e1 a4 [2] de b8 }

  condition:
    any of them
}