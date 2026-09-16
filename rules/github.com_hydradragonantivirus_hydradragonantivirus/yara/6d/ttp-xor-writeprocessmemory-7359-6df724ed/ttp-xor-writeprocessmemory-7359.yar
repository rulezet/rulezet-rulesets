rule TTP_XOR_WriteProcessMemory_7359 {
  strings:
    $key_7359 = { 24 2b [2] 16 09 [2] 10 3c [2] 3e 3c [2] 01 20 }

  condition:
    any of them
}