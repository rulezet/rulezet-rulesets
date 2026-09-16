rule TTP_XOR_WriteProcessMemory_3c69 {
  strings:
    $key_3c69 = { 6b 1b [2] 59 39 [2] 5f 0c [2] 71 0c [2] 4e 10 }

  condition:
    any of them
}