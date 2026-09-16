rule TTP_XOR_WriteProcessMemory_0d3c {
  strings:
    $key_0d3c = { 5a 4e [2] 68 6c [2] 6e 59 [2] 40 59 [2] 7f 45 }

  condition:
    any of them
}