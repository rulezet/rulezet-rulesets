rule TTP_XOR_WriteProcessMemory_2e6e {
  strings:
    $key_2e6e = { 79 1c [2] 4b 3e [2] 4d 0b [2] 63 0b [2] 5c 17 }

  condition:
    any of them
}