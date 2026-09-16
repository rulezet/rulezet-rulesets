rule TTP_XOR_WriteProcessMemory_61b5 {
  strings:
    $key_61b5 = { 36 c7 [2] 04 e5 [2] 02 d0 [2] 2c d0 [2] 13 cc }

  condition:
    any of them
}