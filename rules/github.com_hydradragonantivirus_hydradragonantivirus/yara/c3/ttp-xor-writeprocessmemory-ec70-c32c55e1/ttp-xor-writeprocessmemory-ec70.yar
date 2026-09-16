rule TTP_XOR_WriteProcessMemory_ec70 {
  strings:
    $key_ec70 = { bb 02 [2] 89 20 [2] 8f 15 [2] a1 15 [2] 9e 09 }

  condition:
    any of them
}