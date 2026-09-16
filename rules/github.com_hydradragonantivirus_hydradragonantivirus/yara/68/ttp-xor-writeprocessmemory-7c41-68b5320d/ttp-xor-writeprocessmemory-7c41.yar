rule TTP_XOR_WriteProcessMemory_7c41 {
  strings:
    $key_7c41 = { 2b 33 [2] 19 11 [2] 1f 24 [2] 31 24 [2] 0e 38 }

  condition:
    any of them
}