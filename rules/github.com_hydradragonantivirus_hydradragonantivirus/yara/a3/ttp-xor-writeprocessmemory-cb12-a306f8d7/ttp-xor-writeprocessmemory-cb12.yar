rule TTP_XOR_WriteProcessMemory_cb12 {
  strings:
    $key_cb12 = { 9c 60 [2] ae 42 [2] a8 77 [2] 86 77 [2] b9 6b }

  condition:
    any of them
}