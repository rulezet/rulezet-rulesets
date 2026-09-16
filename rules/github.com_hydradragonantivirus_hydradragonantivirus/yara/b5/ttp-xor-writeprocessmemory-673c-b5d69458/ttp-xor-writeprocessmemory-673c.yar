rule TTP_XOR_WriteProcessMemory_673c {
  strings:
    $key_673c = { 30 4e [2] 02 6c [2] 04 59 [2] 2a 59 [2] 15 45 }

  condition:
    any of them
}