rule TTP_XOR_WriteProcessMemory_7335 {
  strings:
    $key_7335 = { 24 47 [2] 16 65 [2] 10 50 [2] 3e 50 [2] 01 4c }

  condition:
    any of them
}