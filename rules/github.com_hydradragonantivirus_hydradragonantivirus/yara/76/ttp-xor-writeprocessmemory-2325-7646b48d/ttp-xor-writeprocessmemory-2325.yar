rule TTP_XOR_WriteProcessMemory_2325 {
  strings:
    $key_2325 = { 74 57 [2] 46 75 [2] 40 40 [2] 6e 40 [2] 51 5c }

  condition:
    any of them
}