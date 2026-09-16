rule TTP_XOR_WriteProcessMemory_5622 {
  strings:
    $key_5622 = { 01 50 [2] 33 72 [2] 35 47 [2] 1b 47 [2] 24 5b }

  condition:
    any of them
}