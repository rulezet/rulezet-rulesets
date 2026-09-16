rule TTP_XOR_WriteProcessMemory_1196 {
  strings:
    $key_1196 = { 46 e4 [2] 74 c6 [2] 72 f3 [2] 5c f3 [2] 63 ef }

  condition:
    any of them
}