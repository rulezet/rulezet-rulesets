rule TTP_XOR_WriteProcessMemory_625c {
  strings:
    $key_625c = { 35 2e [2] 07 0c [2] 01 39 [2] 2f 39 [2] 10 25 }

  condition:
    any of them
}