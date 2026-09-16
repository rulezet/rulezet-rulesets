rule TTP_XOR_WriteProcessMemory_d25a {
  strings:
    $key_d25a = { 85 28 [2] b7 0a [2] b1 3f [2] 9f 3f [2] a0 23 }

  condition:
    any of them
}