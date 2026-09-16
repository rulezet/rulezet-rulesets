rule TTP_XOR_WriteProcessMemory_c066 {
  strings:
    $key_c066 = { 97 14 [2] a5 36 [2] a3 03 [2] 8d 03 [2] b2 1f }

  condition:
    any of them
}