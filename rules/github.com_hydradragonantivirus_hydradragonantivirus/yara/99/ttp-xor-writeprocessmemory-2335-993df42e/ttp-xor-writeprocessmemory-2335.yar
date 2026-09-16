rule TTP_XOR_WriteProcessMemory_2335 {
  strings:
    $key_2335 = { 74 47 [2] 46 65 [2] 40 50 [2] 6e 50 [2] 51 4c }

  condition:
    any of them
}