rule TTP_XOR_WriteProcessMemory_cb1d {
  strings:
    $key_cb1d = { 9c 6f [2] ae 4d [2] a8 78 [2] 86 78 [2] b9 64 }

  condition:
    any of them
}