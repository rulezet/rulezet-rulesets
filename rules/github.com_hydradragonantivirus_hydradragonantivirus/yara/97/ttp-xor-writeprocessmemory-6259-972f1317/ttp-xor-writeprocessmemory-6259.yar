rule TTP_XOR_WriteProcessMemory_6259 {
  strings:
    $key_6259 = { 35 2b [2] 07 09 [2] 01 3c [2] 2f 3c [2] 10 20 }

  condition:
    any of them
}