rule TTP_XOR_WriteProcessMemory_d8e5 {
  strings:
    $key_d8e5 = { 8f 97 [2] bd b5 [2] bb 80 [2] 95 80 [2] aa 9c }

  condition:
    any of them
}