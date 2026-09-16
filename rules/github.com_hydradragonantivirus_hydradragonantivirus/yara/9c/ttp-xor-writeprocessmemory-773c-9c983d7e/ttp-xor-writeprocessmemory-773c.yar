rule TTP_XOR_WriteProcessMemory_773c {
  strings:
    $key_773c = { 20 4e [2] 12 6c [2] 14 59 [2] 3a 59 [2] 05 45 }

  condition:
    any of them
}