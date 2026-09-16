rule TTP_XOR_WriteProcessMemory_dbe8 {
  strings:
    $key_dbe8 = { 8c 9a [2] be b8 [2] b8 8d [2] 96 8d [2] a9 91 }

  condition:
    any of them
}