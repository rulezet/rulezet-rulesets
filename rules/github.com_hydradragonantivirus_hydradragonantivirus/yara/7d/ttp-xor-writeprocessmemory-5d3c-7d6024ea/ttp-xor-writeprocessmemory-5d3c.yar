rule TTP_XOR_WriteProcessMemory_5d3c {
  strings:
    $key_5d3c = { 0a 4e [2] 38 6c [2] 3e 59 [2] 10 59 [2] 2f 45 }

  condition:
    any of them
}