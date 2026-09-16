rule TTP_XOR_WriteProcessMemory_ec25 {
  strings:
    $key_ec25 = { bb 57 [2] 89 75 [2] 8f 40 [2] a1 40 [2] 9e 5c }

  condition:
    any of them
}