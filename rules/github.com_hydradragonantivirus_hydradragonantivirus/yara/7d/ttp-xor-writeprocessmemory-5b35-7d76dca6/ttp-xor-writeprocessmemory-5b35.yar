rule TTP_XOR_WriteProcessMemory_5b35 {
  strings:
    $key_5b35 = { 0c 47 [2] 3e 65 [2] 38 50 [2] 16 50 [2] 29 4c }

  condition:
    any of them
}