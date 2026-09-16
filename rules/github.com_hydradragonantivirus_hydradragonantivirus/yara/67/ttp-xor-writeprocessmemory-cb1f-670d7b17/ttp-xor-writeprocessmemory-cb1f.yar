rule TTP_XOR_WriteProcessMemory_cb1f {
  strings:
    $key_cb1f = { 9c 6d [2] ae 4f [2] a8 7a [2] 86 7a [2] b9 66 }

  condition:
    any of them
}