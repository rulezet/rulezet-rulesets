rule TTP_XOR_WriteProcessMemory_cb08 {
  strings:
    $key_cb08 = { 9c 7a [2] ae 58 [2] a8 6d [2] 86 6d [2] b9 71 }

  condition:
    any of them
}