rule TTP_XOR_WriteProcessMemory_380e {
  strings:
    $key_380e = { 6f 7c [2] 5d 5e [2] 5b 6b [2] 75 6b [2] 4a 77 }

  condition:
    any of them
}