rule TTP_XOR_WriteProcessMemory_6d3e {
  strings:
    $key_6d3e = { 3a 4c [2] 08 6e [2] 0e 5b [2] 20 5b [2] 1f 47 }

  condition:
    any of them
}