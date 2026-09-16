rule TTP_XOR_WriteProcessMemory_2e29 {
  strings:
    $key_2e29 = { 79 5b [2] 4b 79 [2] 4d 4c [2] 63 4c [2] 5c 50 }

  condition:
    any of them
}