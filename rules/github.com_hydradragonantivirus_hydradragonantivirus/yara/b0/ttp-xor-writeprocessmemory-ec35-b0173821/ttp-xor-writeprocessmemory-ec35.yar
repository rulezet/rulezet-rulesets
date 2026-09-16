rule TTP_XOR_WriteProcessMemory_ec35 {
  strings:
    $key_ec35 = { bb 47 [2] 89 65 [2] 8f 50 [2] a1 50 [2] 9e 4c }

  condition:
    any of them
}