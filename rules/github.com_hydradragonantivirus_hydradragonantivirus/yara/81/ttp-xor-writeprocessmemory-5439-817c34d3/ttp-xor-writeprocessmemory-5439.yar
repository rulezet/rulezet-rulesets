rule TTP_XOR_WriteProcessMemory_5439 {
  strings:
    $key_5439 = { 03 4b [2] 31 69 [2] 37 5c [2] 19 5c [2] 26 40 }

  condition:
    any of them
}