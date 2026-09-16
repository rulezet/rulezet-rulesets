rule TTP_XOR_WriteProcessMemory_69f9 {
  strings:
    $key_69f9 = { 3e 8b [2] 0c a9 [2] 0a 9c [2] 24 9c [2] 1b 80 }

  condition:
    any of them
}