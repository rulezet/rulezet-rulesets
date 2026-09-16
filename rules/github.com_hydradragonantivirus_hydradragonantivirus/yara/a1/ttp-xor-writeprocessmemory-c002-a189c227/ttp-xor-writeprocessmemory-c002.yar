rule TTP_XOR_WriteProcessMemory_c002 {
  strings:
    $key_c002 = { 97 70 [2] a5 52 [2] a3 67 [2] 8d 67 [2] b2 7b }

  condition:
    any of them
}