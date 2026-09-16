rule TTP_XOR_WriteProcessMemory_052e {
  strings:
    $key_052e = { 52 5c [2] 60 7e [2] 66 4b [2] 48 4b [2] 77 57 }

  condition:
    any of them
}