rule TTP_XOR_WriteProcessMemory_2319 {
  strings:
    $key_2319 = { 74 6b [2] 46 49 [2] 40 7c [2] 6e 7c [2] 51 60 }

  condition:
    any of them
}