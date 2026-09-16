rule TTP_XOR_WriteProcessMemory_2b3e {
  strings:
    $key_2b3e = { 7c 4c [2] 4e 6e [2] 48 5b [2] 66 5b [2] 59 47 }

  condition:
    any of them
}