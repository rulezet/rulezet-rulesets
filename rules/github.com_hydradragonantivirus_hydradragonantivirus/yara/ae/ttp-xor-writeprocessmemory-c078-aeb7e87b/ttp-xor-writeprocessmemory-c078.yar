rule TTP_XOR_WriteProcessMemory_c078 {
  strings:
    $key_c078 = { 97 0a [2] a5 28 [2] a3 1d [2] 8d 1d [2] b2 01 }

  condition:
    any of them
}