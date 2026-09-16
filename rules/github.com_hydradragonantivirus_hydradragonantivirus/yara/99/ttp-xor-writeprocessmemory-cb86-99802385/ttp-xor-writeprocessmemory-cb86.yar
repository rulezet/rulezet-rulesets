rule TTP_XOR_WriteProcessMemory_cb86 {
  strings:
    $key_cb86 = { 9c f4 [2] ae d6 [2] a8 e3 [2] 86 e3 [2] b9 ff }

  condition:
    any of them
}