rule TTP_XOR_WriteProcessMemory_7c30 {
  strings:
    $key_7c30 = { 2b 42 [2] 19 60 [2] 1f 55 [2] 31 55 [2] 0e 49 }

  condition:
    any of them
}