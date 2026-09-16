rule TTP_XOR_WriteProcessMemory_1167 {
  strings:
    $key_1167 = { 46 15 [2] 74 37 [2] 72 02 [2] 5c 02 [2] 63 1e }

  condition:
    any of them
}