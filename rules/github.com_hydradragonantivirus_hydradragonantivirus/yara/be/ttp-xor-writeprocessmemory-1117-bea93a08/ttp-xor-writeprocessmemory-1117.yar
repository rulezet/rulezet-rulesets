rule TTP_XOR_WriteProcessMemory_1117 {
  strings:
    $key_1117 = { 46 65 [2] 74 47 [2] 72 72 [2] 5c 72 [2] 63 6e }

  condition:
    any of them
}