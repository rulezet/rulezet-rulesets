rule TTP_XOR_WriteProcessMemory_ec37 {
  strings:
    $key_ec37 = { bb 45 [2] 89 67 [2] 8f 52 [2] a1 52 [2] 9e 4e }

  condition:
    any of them
}