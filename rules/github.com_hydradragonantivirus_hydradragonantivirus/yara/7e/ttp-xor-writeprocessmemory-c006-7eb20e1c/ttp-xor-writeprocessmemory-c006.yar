rule TTP_XOR_WriteProcessMemory_c006 {
  strings:
    $key_c006 = { 97 74 [2] a5 56 [2] a3 63 [2] 8d 63 [2] b2 7f }

  condition:
    any of them
}