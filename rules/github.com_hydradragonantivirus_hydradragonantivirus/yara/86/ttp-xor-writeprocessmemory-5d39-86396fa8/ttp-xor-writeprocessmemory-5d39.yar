rule TTP_XOR_WriteProcessMemory_5d39 {
  strings:
    $key_5d39 = { 0a 4b [2] 38 69 [2] 3e 5c [2] 10 5c [2] 2f 40 }

  condition:
    any of them
}