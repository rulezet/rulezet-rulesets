rule TTP_XOR_WriteProcessMemory_ec55 {
  strings:
    $key_ec55 = { bb 27 [2] 89 05 [2] 8f 30 [2] a1 30 [2] 9e 2c }

  condition:
    any of them
}