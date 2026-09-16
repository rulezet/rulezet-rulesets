rule TTP_XOR_WriteProcessMemory_3335 {
  strings:
    $key_3335 = { 64 47 [2] 56 65 [2] 50 50 [2] 7e 50 [2] 41 4c }

  condition:
    any of them
}