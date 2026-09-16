rule TTP_XOR_WriteProcessMemory_375c {
  strings:
    $key_375c = { 60 2e [2] 52 0c [2] 54 39 [2] 7a 39 [2] 45 25 }

  condition:
    any of them
}