rule TTP_XOR_WriteProcessMemory_3b35 {
  strings:
    $key_3b35 = { 6c 47 [2] 5e 65 [2] 58 50 [2] 76 50 [2] 49 4c }

  condition:
    any of them
}