rule TTP_XOR_WriteProcessMemory_5959 {
  strings:
    $key_5959 = { 0e 2b [2] 3c 09 [2] 3a 3c [2] 14 3c [2] 2b 20 }

  condition:
    any of them
}