rule TTP_XOR_WriteProcessMemory_fbc0 {
  strings:
    $key_fbc0 = { ac b2 [2] 9e 90 [2] 98 a5 [2] b6 a5 [2] 89 b9 }

  condition:
    any of them
}