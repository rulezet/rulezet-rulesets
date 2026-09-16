rule TTP_XOR_WriteProcessMemory_c118 {
  strings:
    $key_c118 = { 96 6a [2] a4 48 [2] a2 7d [2] 8c 7d [2] b3 61 }

  condition:
    any of them
}