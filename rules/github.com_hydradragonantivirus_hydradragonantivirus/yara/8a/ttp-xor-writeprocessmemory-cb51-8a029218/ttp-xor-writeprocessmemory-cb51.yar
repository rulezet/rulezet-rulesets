rule TTP_XOR_WriteProcessMemory_cb51 {
  strings:
    $key_cb51 = { 9c 23 [2] ae 01 [2] a8 34 [2] 86 34 [2] b9 28 }

  condition:
    any of them
}