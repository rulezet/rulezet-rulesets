rule TTP_XOR_WriteProcessMemory_2329 {
  strings:
    $key_2329 = { 74 5b [2] 46 79 [2] 40 4c [2] 6e 4c [2] 51 50 }

  condition:
    any of them
}