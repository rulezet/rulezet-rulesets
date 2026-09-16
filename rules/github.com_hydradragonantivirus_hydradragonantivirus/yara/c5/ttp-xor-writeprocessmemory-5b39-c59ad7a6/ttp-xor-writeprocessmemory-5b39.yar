rule TTP_XOR_WriteProcessMemory_5b39 {
  strings:
    $key_5b39 = { 0c 4b [2] 3e 69 [2] 38 5c [2] 16 5c [2] 29 40 }

  condition:
    any of them
}