rule TTP_XOR_WriteProcessMemory_056e {
  strings:
    $key_056e = { 52 1c [2] 60 3e [2] 66 0b [2] 48 0b [2] 77 17 }

  condition:
    any of them
}