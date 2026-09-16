rule TTP_XOR_WriteProcessMemory_1672 {
  strings:
    $key_1672 = { 41 00 [2] 73 22 [2] 75 17 [2] 5b 17 [2] 64 0b }

  condition:
    any of them
}