rule TTP_XOR_WriteProcessMemory_cb2f {
  strings:
    $key_cb2f = { 9c 5d [2] ae 7f [2] a8 4a [2] 86 4a [2] b9 56 }

  condition:
    any of them
}