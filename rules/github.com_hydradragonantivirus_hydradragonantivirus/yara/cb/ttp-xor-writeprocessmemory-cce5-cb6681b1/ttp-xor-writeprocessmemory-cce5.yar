rule TTP_XOR_WriteProcessMemory_cce5 {
  strings:
    $key_cce5 = { 9b 97 [2] a9 b5 [2] af 80 [2] 81 80 [2] be 9c }

  condition:
    any of them
}