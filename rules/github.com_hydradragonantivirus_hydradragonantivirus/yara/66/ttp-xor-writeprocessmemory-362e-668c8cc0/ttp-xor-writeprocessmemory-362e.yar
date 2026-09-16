rule TTP_XOR_WriteProcessMemory_362e {
  strings:
    $key_362e = { 61 5c [2] 53 7e [2] 55 4b [2] 7b 4b [2] 44 57 }

  condition:
    any of them
}