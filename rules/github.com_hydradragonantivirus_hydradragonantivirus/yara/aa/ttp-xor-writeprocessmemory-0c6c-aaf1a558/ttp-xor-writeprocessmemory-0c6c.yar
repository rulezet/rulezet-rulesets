rule TTP_XOR_WriteProcessMemory_0c6c {
  strings:
    $key_0c6c = { 5b 1e [2] 69 3c [2] 6f 09 [2] 41 09 [2] 7e 15 }

  condition:
    any of them
}