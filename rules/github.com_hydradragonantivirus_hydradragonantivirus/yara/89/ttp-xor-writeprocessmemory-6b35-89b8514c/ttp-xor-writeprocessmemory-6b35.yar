rule TTP_XOR_WriteProcessMemory_6b35 {
  strings:
    $key_6b35 = { 3c 47 [2] 0e 65 [2] 08 50 [2] 26 50 [2] 19 4c }

  condition:
    any of them
}