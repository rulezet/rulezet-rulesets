rule TTP_XOR_WriteProcessMemory_6d31 {
  strings:
    $key_6d31 = { 3a 43 [2] 08 61 [2] 0e 54 [2] 20 54 [2] 1f 48 }

  condition:
    any of them
}