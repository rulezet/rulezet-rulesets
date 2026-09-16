rule TTP_XOR_WriteProcessMemory_791e {
  strings:
    $key_791e = { 2e 6c [2] 1c 4e [2] 1a 7b [2] 34 7b [2] 0b 67 }

  condition:
    any of them
}