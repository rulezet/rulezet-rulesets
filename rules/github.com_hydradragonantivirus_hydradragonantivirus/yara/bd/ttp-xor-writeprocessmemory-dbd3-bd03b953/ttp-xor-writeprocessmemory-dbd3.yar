rule TTP_XOR_WriteProcessMemory_dbd3 {
  strings:
    $key_dbd3 = { 8c a1 [2] be 83 [2] b8 b6 [2] 96 b6 [2] a9 aa }

  condition:
    any of them
}