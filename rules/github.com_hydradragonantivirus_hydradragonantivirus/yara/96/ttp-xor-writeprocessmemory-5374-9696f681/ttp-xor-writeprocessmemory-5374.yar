rule TTP_XOR_WriteProcessMemory_5374 {
  strings:
    $key_5374 = { 04 06 [2] 36 24 [2] 30 11 [2] 1e 11 [2] 21 0d }

  condition:
    any of them
}