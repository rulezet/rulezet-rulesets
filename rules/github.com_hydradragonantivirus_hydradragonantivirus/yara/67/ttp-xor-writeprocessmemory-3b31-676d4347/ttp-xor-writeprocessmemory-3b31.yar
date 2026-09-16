rule TTP_XOR_WriteProcessMemory_3b31 {
  strings:
    $key_3b31 = { 6c 43 [2] 5e 61 [2] 58 54 [2] 76 54 [2] 49 48 }

  condition:
    any of them
}