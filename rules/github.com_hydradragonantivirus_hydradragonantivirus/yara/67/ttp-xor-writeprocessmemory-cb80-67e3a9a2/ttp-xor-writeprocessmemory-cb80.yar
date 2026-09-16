rule TTP_XOR_WriteProcessMemory_cb80 {
  strings:
    $key_cb80 = { 9c f2 [2] ae d0 [2] a8 e5 [2] 86 e5 [2] b9 f9 }

  condition:
    any of them
}