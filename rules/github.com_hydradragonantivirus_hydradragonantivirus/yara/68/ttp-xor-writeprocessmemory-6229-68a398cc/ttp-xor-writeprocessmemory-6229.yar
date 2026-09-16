rule TTP_XOR_WriteProcessMemory_6229 {
  strings:
    $key_6229 = { 35 5b [2] 07 79 [2] 01 4c [2] 2f 4c [2] 10 50 }

  condition:
    any of them
}