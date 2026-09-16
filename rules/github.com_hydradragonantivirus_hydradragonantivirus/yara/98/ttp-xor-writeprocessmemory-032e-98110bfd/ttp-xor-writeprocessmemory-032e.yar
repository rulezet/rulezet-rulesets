rule TTP_XOR_WriteProcessMemory_032e {
  strings:
    $key_032e = { 54 5c [2] 66 7e [2] 60 4b [2] 4e 4b [2] 71 57 }

  condition:
    any of them
}