rule TTP_XOR_WriteProcessMemory_dbe2 {
  strings:
    $key_dbe2 = { 8c 90 [2] be b2 [2] b8 87 [2] 96 87 [2] a9 9b }

  condition:
    any of them
}