rule TTP_XOR_WriteProcessMemory_532e {
  strings:
    $key_532e = { 04 5c [2] 36 7e [2] 30 4b [2] 1e 4b [2] 21 57 }

  condition:
    any of them
}