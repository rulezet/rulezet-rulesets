rule TTP_XOR_WriteProcessMemory_7769 {
  strings:
    $key_7769 = { 20 1b [2] 12 39 [2] 14 0c [2] 3a 0c [2] 05 10 }

  condition:
    any of them
}