rule TTP_XOR_WriteProcessMemory_cb44 {
  strings:
    $key_cb44 = { 9c 36 [2] ae 14 [2] a8 21 [2] 86 21 [2] b9 3d }

  condition:
    any of them
}