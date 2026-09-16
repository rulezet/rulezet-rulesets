rule TTP_XOR_WriteProcessMemory_d8e9 {
  strings:
    $key_d8e9 = { 8f 9b [2] bd b9 [2] bb 8c [2] 95 8c [2] aa 90 }

  condition:
    any of them
}