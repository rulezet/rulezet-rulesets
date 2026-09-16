rule TTP_XOR_WriteProcessMemory_c008 {
  strings:
    $key_c008 = { 97 7a [2] a5 58 [2] a3 6d [2] 8d 6d [2] b2 71 }

  condition:
    any of them
}