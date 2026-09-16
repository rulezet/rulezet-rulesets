rule TTP_XOR_WriteProcessMemory_cb01 {
  strings:
    $key_cb01 = { 9c 73 [2] ae 51 [2] a8 64 [2] 86 64 [2] b9 78 }

  condition:
    any of them
}