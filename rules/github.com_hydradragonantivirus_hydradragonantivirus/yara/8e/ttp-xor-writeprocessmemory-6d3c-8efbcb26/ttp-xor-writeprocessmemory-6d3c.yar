rule TTP_XOR_WriteProcessMemory_6d3c {
  strings:
    $key_6d3c = { 3a 4e [2] 08 6c [2] 0e 59 [2] 20 59 [2] 1f 45 }

  condition:
    any of them
}