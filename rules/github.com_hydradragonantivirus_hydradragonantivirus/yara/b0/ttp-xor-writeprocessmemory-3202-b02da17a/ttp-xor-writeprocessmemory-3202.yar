rule TTP_XOR_WriteProcessMemory_3202 {
  strings:
    $key_3202 = { 65 70 [2] 57 52 [2] 51 67 [2] 7f 67 [2] 40 7b }

  condition:
    any of them
}