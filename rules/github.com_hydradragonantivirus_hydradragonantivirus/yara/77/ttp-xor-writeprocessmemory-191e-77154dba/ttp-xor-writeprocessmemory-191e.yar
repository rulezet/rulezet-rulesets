rule TTP_XOR_WriteProcessMemory_191e {
  strings:
    $key_191e = { 4e 6c [2] 7c 4e [2] 7a 7b [2] 54 7b [2] 6b 67 }

  condition:
    any of them
}