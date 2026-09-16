rule TTP_XOR_WriteProcessMemory_af88 {
  strings:
    $key_af88 = { f8 fa [2] ca d8 [2] cc ed [2] e2 ed [2] dd f1 }

  condition:
    any of them
}