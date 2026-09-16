rule TTP_XOR_WriteProcessMemory_cb38 {
  strings:
    $key_cb38 = { 9c 4a [2] ae 68 [2] a8 5d [2] 86 5d [2] b9 41 }

  condition:
    any of them
}