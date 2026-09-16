rule TTP_XOR_WriteProcessMemory_cb30 {
  strings:
    $key_cb30 = { 9c 42 [2] ae 60 [2] a8 55 [2] 86 55 [2] b9 49 }

  condition:
    any of them
}