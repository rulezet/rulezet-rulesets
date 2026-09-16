rule TTP_XOR_WriteProcessMemory_6239 {
  strings:
    $key_6239 = { 35 4b [2] 07 69 [2] 01 5c [2] 2f 5c [2] 10 40 }

  condition:
    any of them
}