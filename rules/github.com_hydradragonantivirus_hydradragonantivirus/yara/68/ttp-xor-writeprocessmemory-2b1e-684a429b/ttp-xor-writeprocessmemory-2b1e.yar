rule TTP_XOR_WriteProcessMemory_2b1e {
  strings:
    $key_2b1e = { 7c 6c [2] 4e 4e [2] 48 7b [2] 66 7b [2] 59 67 }

  condition:
    any of them
}