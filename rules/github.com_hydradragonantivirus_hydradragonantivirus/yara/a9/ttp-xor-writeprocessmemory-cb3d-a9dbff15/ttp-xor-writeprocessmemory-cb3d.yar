rule TTP_XOR_WriteProcessMemory_cb3d {
  strings:
    $key_cb3d = { 9c 4f [2] ae 6d [2] a8 58 [2] 86 58 [2] b9 44 }

  condition:
    any of them
}