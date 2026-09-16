rule TTP_XOR_WriteProcessMemory_cb3f {
  strings:
    $key_cb3f = { 9c 4d [2] ae 6f [2] a8 5a [2] 86 5a [2] b9 46 }

  condition:
    any of them
}