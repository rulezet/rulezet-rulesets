rule TTP_XOR_WriteProcessMemory_2d3e {
  strings:
    $key_2d3e = { 7a 4c [2] 48 6e [2] 4e 5b [2] 60 5b [2] 5f 47 }

  condition:
    any of them
}