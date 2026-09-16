rule TTP_XOR_WriteProcessMemory_1134 {
  strings:
    $key_1134 = { 46 46 [2] 74 64 [2] 72 51 [2] 5c 51 [2] 63 4d }

  condition:
    any of them
}