rule TTP_XOR_WriteProcessMemory_2e3e {
  strings:
    $key_2e3e = { 79 4c [2] 4b 6e [2] 4d 5b [2] 63 5b [2] 5c 47 }

  condition:
    any of them
}