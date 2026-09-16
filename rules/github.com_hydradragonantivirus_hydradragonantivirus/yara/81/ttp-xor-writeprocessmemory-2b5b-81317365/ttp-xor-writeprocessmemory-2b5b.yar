rule TTP_XOR_WriteProcessMemory_2b5b {
  strings:
    $key_2b5b = { 7c 29 [2] 4e 0b [2] 48 3e [2] 66 3e [2] 59 22 }

  condition:
    any of them
}