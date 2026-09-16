rule TTP_XOR_WriteProcessMemory_2b4e {
  strings:
    $key_2b4e = { 7c 3c [2] 4e 1e [2] 48 2b [2] 66 2b [2] 59 37 }

  condition:
    any of them
}