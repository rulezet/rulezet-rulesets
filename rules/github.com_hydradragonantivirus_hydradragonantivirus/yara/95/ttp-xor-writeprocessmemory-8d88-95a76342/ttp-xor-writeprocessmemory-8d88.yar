rule TTP_XOR_WriteProcessMemory_8d88 {
  strings:
    $key_8d88 = { da fa [2] e8 d8 [2] ee ed [2] c0 ed [2] ff f1 }

  condition:
    any of them
}