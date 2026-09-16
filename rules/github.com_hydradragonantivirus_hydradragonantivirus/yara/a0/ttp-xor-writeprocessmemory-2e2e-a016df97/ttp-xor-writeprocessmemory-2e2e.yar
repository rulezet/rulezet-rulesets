rule TTP_XOR_WriteProcessMemory_2e2e {
  strings:
    $key_2e2e = { 79 5c [2] 4b 7e [2] 4d 4b [2] 63 4b [2] 5c 57 }

  condition:
    any of them
}