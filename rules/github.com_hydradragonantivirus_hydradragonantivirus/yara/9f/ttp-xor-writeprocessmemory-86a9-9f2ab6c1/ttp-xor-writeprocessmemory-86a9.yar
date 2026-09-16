rule TTP_XOR_WriteProcessMemory_86a9 {
  strings:
    $key_86a9 = { d1 db [2] e3 f9 [2] e5 cc [2] cb cc [2] f4 d0 }

  condition:
    any of them
}