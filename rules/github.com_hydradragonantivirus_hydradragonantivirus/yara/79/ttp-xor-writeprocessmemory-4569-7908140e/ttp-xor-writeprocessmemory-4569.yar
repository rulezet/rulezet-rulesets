rule TTP_XOR_WriteProcessMemory_4569 {
  strings:
    $key_4569 = { 12 1b [2] 20 39 [2] 26 0c [2] 08 0c [2] 37 10 }

  condition:
    any of them
}