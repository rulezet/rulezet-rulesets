rule TTP_XOR_WriteProcessMemory_2b6e {
  strings:
    $key_2b6e = { 7c 1c [2] 4e 3e [2] 48 0b [2] 66 0b [2] 59 17 }

  condition:
    any of them
}