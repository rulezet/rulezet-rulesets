rule TTP_XOR_WriteProcessMemory_3541 {
  strings:
    $key_3541 = { 62 33 [2] 50 11 [2] 56 24 [2] 78 24 [2] 47 38 }

  condition:
    any of them
}