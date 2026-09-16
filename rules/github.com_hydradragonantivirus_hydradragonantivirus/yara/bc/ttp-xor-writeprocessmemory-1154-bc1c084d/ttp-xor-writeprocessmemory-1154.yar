rule TTP_XOR_WriteProcessMemory_1154 {
  strings:
    $key_1154 = { 46 26 [2] 74 04 [2] 72 31 [2] 5c 31 [2] 63 2d }

  condition:
    any of them
}