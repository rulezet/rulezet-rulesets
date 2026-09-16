rule TTP_XOR_WriteProcessMemory_7659 {
  strings:
    $key_7659 = { 21 2b [2] 13 09 [2] 15 3c [2] 3b 3c [2] 04 20 }

  condition:
    any of them
}