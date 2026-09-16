rule TTP_XOR_WriteProcessMemory_c7e8 {
  strings:
    $key_c7e8 = { 90 9a [2] a2 b8 [2] a4 8d [2] 8a 8d [2] b5 91 }

  condition:
    any of them
}