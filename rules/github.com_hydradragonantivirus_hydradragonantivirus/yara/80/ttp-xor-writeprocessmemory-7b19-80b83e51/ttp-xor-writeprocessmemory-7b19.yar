rule TTP_XOR_WriteProcessMemory_7b19 {
  strings:
    $key_7b19 = { 2c 6b [2] 1e 49 [2] 18 7c [2] 36 7c [2] 09 60 }

  condition:
    any of them
}