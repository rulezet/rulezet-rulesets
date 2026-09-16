rule TTP_XOR_WriteProcessMemory_3e3e {
  strings:
    $key_3e3e = { 69 4c [2] 5b 6e [2] 5d 5b [2] 73 5b [2] 4c 47 }

  condition:
    any of them
}