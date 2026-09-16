rule TTP_XOR_WriteProcessMemory_d8e4 {
  strings:
    $key_d8e4 = { 8f 96 [2] bd b4 [2] bb 81 [2] 95 81 [2] aa 9d }

  condition:
    any of them
}