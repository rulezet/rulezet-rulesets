rule TTP_XOR_WriteProcessMemory_c076 {
  strings:
    $key_c076 = { 97 04 [2] a5 26 [2] a3 13 [2] 8d 13 [2] b2 0f }

  condition:
    any of them
}