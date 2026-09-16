rule TTP_XOR_WriteProcessMemory_cb58 {
  strings:
    $key_cb58 = { 9c 2a [2] ae 08 [2] a8 3d [2] 86 3d [2] b9 21 }

  condition:
    any of them
}