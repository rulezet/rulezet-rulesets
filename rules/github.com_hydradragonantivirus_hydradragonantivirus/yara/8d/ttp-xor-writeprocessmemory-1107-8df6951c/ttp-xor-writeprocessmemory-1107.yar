rule TTP_XOR_WriteProcessMemory_1107 {
  strings:
    $key_1107 = { 46 75 [2] 74 57 [2] 72 62 [2] 5c 62 [2] 63 7e }

  condition:
    any of them
}