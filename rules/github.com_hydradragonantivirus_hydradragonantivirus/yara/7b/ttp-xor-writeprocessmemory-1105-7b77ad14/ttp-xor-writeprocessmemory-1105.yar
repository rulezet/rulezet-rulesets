rule TTP_XOR_WriteProcessMemory_1105 {
  strings:
    $key_1105 = { 46 77 [2] 74 55 [2] 72 60 [2] 5c 60 [2] 63 7c }

  condition:
    any of them
}