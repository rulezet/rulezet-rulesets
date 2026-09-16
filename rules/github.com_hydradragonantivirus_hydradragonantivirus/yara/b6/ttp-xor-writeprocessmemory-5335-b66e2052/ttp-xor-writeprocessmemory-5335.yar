rule TTP_XOR_WriteProcessMemory_5335 {
  strings:
    $key_5335 = { 04 47 [2] 36 65 [2] 30 50 [2] 1e 50 [2] 21 4c }

  condition:
    any of them
}