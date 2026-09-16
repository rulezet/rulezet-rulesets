rule TTP_XOR_WriteProcessMemory_cb98 {
  strings:
    $key_cb98 = { 9c ea [2] ae c8 [2] a8 fd [2] 86 fd [2] b9 e1 }

  condition:
    any of them
}