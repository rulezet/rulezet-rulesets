rule TTP_XOR_WriteProcessMemory_cb85 {
  strings:
    $key_cb85 = { 9c f7 [2] ae d5 [2] a8 e0 [2] 86 e0 [2] b9 fc }

  condition:
    any of them
}