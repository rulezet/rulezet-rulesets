rule TTP_XOR_WriteProcessMemory_c068 {
  strings:
    $key_c068 = { 97 1a [2] a5 38 [2] a3 0d [2] 8d 0d [2] b2 11 }

  condition:
    any of them
}