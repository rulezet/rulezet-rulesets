rule TTP_XOR_WriteProcessMemory_5659 {
  strings:
    $key_5659 = { 01 2b [2] 33 09 [2] 35 3c [2] 1b 3c [2] 24 20 }

  condition:
    any of them
}