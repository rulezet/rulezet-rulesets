rule TTP_XOR_WriteProcessMemory_cb82 {
  strings:
    $key_cb82 = { 9c f0 [2] ae d2 [2] a8 e7 [2] 86 e7 [2] b9 fb }

  condition:
    any of them
}