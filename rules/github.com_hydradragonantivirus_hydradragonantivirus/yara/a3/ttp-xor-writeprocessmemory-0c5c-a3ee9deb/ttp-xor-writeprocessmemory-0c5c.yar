rule TTP_XOR_WriteProcessMemory_0c5c {
  strings:
    $key_0c5c = { 5b 2e [2] 69 0c [2] 6f 39 [2] 41 39 [2] 7e 25 }

  condition:
    any of them
}