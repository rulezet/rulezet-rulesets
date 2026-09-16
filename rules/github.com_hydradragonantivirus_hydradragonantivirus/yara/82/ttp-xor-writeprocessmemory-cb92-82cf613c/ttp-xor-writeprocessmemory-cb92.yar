rule TTP_XOR_WriteProcessMemory_cb92 {
  strings:
    $key_cb92 = { 9c e0 [2] ae c2 [2] a8 f7 [2] 86 f7 [2] b9 eb }

  condition:
    any of them
}