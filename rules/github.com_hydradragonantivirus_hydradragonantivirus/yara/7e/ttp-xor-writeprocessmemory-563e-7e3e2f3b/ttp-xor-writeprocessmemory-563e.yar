rule TTP_XOR_WriteProcessMemory_563e {
  strings:
    $key_563e = { 01 4c [2] 33 6e [2] 35 5b [2] 1b 5b [2] 24 47 }

  condition:
    any of them
}