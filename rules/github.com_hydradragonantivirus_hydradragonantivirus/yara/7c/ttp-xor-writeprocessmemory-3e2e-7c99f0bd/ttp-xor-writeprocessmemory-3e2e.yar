rule TTP_XOR_WriteProcessMemory_3e2e {
  strings:
    $key_3e2e = { 69 5c [2] 5b 7e [2] 5d 4b [2] 73 4b [2] 4c 57 }

  condition:
    any of them
}