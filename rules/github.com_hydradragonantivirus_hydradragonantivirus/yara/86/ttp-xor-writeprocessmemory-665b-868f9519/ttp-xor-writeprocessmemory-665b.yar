rule TTP_XOR_WriteProcessMemory_665b {
  strings:
    $key_665b = { 31 29 [2] 03 0b [2] 05 3e [2] 2b 3e [2] 14 22 }

  condition:
    any of them
}