rule TTP_XOR_WriteProcessMemory_cb4d {
  strings:
    $key_cb4d = { 9c 3f [2] ae 1d [2] a8 28 [2] 86 28 [2] b9 34 }

  condition:
    any of them
}