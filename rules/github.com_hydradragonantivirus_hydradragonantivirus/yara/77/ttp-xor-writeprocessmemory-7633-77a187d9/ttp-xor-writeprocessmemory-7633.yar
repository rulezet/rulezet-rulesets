rule TTP_XOR_WriteProcessMemory_7633 {
  strings:
    $key_7633 = { 21 41 [2] 13 63 [2] 15 56 [2] 3b 56 [2] 04 4a }

  condition:
    any of them
}