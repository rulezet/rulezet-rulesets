rule TTP_XOR_WriteProcessMemory_c018 {
  strings:
    $key_c018 = { 97 6a [2] a5 48 [2] a3 7d [2] 8d 7d [2] b2 61 }

  condition:
    any of them
}