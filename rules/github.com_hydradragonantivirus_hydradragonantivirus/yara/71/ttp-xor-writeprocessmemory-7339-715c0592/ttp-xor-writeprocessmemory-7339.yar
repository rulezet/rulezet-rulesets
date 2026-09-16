rule TTP_XOR_WriteProcessMemory_7339 {
  strings:
    $key_7339 = { 24 4b [2] 16 69 [2] 10 5c [2] 3e 5c [2] 01 40 }

  condition:
    any of them
}