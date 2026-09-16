rule TTP_XOR_WriteProcessMemory_cb1a {
  strings:
    $key_cb1a = { 9c 68 [2] ae 4a [2] a8 7f [2] 86 7f [2] b9 63 }

  condition:
    any of them
}