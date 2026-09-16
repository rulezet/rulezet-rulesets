rule TTP_XOR_WriteProcessMemory_7613 {
  strings:
    $key_7613 = { 21 61 [2] 13 43 [2] 15 76 [2] 3b 76 [2] 04 6a }

  condition:
    any of them
}