rule TTP_XOR_WriteProcessMemory_7b39 {
  strings:
    $key_7b39 = { 2c 4b [2] 1e 69 [2] 18 5c [2] 36 5c [2] 09 40 }

  condition:
    any of them
}