rule TTP_XOR_WriteProcessMemory_3969 {
  strings:
    $key_3969 = { 6e 1b [2] 5c 39 [2] 5a 0c [2] 74 0c [2] 4b 10 }

  condition:
    any of them
}