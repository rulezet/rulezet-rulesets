rule TTP_XOR_WriteProcessMemory_c128 {
  strings:
    $key_c128 = { 96 5a [2] a4 78 [2] a2 4d [2] 8c 4d [2] b3 51 }

  condition:
    any of them
}