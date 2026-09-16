rule TTP_XOR_WriteProcessMemory_ccc7 {
  strings:
    $key_ccc7 = { 9b b5 [2] a9 97 [2] af a2 [2] 81 a2 [2] be be }

  condition:
    any of them
}