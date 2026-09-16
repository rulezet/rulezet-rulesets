rule TTP_XOR_WriteProcessMemory_5633 {
  strings:
    $key_5633 = { 01 41 [2] 33 63 [2] 35 56 [2] 1b 56 [2] 24 4a }

  condition:
    any of them
}