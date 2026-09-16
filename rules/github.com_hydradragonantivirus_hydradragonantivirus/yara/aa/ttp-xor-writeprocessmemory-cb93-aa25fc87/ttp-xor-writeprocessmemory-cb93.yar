rule TTP_XOR_WriteProcessMemory_cb93 {
  strings:
    $key_cb93 = { 9c e1 [2] ae c3 [2] a8 f6 [2] 86 f6 [2] b9 ea }

  condition:
    any of them
}