rule TTP_XOR_WriteProcessMemory_4669 {
  strings:
    $key_4669 = { 11 1b [2] 23 39 [2] 25 0c [2] 0b 0c [2] 34 10 }

  condition:
    any of them
}