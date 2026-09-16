rule TTP_XOR_WriteProcessMemory_1764 {
  strings:
    $key_1764 = { 40 16 [2] 72 34 [2] 74 01 [2] 5a 01 [2] 65 1d }

  condition:
    any of them
}