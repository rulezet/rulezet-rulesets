rule TTP_XOR_WriteProcessMemory_1b39 {
  strings:
    $key_1b39 = { 4c 4b [2] 7e 69 [2] 78 5c [2] 56 5c [2] 69 40 }

  condition:
    any of them
}