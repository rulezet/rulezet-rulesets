rule TTP_XOR_WriteProcessMemory_670c {
  strings:
    $key_670c = { 30 7e [2] 02 5c [2] 04 69 [2] 2a 69 [2] 15 75 }

  condition:
    any of them
}