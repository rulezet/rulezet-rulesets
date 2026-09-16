rule TTP_XOR_WriteProcessMemory_cb90 {
  strings:
    $key_cb90 = { 9c e2 [2] ae c0 [2] a8 f5 [2] 86 f5 [2] b9 e9 }

  condition:
    any of them
}