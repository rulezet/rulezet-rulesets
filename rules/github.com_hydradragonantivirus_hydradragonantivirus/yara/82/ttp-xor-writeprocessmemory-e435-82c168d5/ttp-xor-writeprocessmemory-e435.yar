rule TTP_XOR_WriteProcessMemory_e435 {
  strings:
    $key_e435 = { b3 47 [2] 81 65 [2] 87 50 [2] a9 50 [2] 96 4c }

  condition:
    any of them
}