rule TTP_XOR_WriteProcessMemory_8db2 {
  strings:
    $key_8db2 = { da c0 [2] e8 e2 [2] ee d7 [2] c0 d7 [2] ff cb }

  condition:
    any of them
}