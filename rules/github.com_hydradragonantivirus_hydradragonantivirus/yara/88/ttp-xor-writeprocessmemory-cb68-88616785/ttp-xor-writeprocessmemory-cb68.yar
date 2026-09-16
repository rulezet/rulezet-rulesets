rule TTP_XOR_WriteProcessMemory_cb68 {
  strings:
    $key_cb68 = { 9c 1a [2] ae 38 [2] a8 0d [2] 86 0d [2] b9 11 }

  condition:
    any of them
}