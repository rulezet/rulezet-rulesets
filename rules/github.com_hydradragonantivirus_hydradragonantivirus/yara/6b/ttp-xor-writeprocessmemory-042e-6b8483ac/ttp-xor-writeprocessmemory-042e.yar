rule TTP_XOR_WriteProcessMemory_042e {
  strings:
    $key_042e = { 53 5c [2] 61 7e [2] 67 4b [2] 49 4b [2] 76 57 }

  condition:
    any of them
}