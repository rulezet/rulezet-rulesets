rule TTP_XOR_WriteProcessMemory_ec67 {
  strings:
    $key_ec67 = { bb 15 [2] 89 37 [2] 8f 02 [2] a1 02 [2] 9e 1e }

  condition:
    any of them
}