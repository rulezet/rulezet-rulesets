rule TTP_XOR_WriteProcessMemory_5d31 {
  strings:
    $key_5d31 = { 0a 43 [2] 38 61 [2] 3e 54 [2] 10 54 [2] 2f 48 }

  condition:
    any of them
}