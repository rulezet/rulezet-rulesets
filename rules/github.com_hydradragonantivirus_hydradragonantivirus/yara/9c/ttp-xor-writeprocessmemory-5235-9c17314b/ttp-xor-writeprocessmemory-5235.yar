rule TTP_XOR_WriteProcessMemory_5235 {
  strings:
    $key_5235 = { 05 47 [2] 37 65 [2] 31 50 [2] 1f 50 [2] 20 4c }

  condition:
    any of them
}