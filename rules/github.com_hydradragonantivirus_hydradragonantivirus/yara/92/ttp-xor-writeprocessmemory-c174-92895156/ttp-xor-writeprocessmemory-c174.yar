rule TTP_XOR_WriteProcessMemory_c174 {
  strings:
    $key_c174 = { 96 06 [2] a4 24 [2] a2 11 [2] 8c 11 [2] b3 0d }

  condition:
    any of them
}