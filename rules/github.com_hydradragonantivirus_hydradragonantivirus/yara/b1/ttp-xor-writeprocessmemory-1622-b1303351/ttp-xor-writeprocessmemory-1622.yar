rule TTP_XOR_WriteProcessMemory_1622 {
  strings:
    $key_1622 = { 41 50 [2] 73 72 [2] 75 47 [2] 5b 47 [2] 64 5b }

  condition:
    any of them
}