rule TTP_XOR_WriteProcessMemory_7965 {
  strings:
    $key_7965 = { 2e 17 [2] 1c 35 [2] 1a 00 [2] 34 00 [2] 0b 1c }

  condition:
    any of them
}