rule TTP_XOR_WriteProcessMemory_5d59 {
  strings:
    $key_5d59 = { 0a 2b [2] 38 09 [2] 3e 3c [2] 10 3c [2] 2f 20 }

  condition:
    any of them
}