rule TTP_XOR_WriteProcessMemory_c30a {
  strings:
    $key_c30a = { 94 78 [2] a6 5a [2] a0 6f [2] 8e 6f [2] b1 73 }

  condition:
    any of them
}