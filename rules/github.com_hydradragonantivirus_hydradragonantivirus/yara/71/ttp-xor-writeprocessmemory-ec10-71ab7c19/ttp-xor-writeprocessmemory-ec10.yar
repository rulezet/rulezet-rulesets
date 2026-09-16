rule TTP_XOR_WriteProcessMemory_ec10 {
  strings:
    $key_ec10 = { bb 62 [2] 89 40 [2] 8f 75 [2] a1 75 [2] 9e 69 }

  condition:
    any of them
}