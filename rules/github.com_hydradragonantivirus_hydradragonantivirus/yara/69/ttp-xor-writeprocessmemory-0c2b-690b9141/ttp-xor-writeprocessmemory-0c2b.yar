rule TTP_XOR_WriteProcessMemory_0c2b {
  strings:
    $key_0c2b = { 5b 59 [2] 69 7b [2] 6f 4e [2] 41 4e [2] 7e 52 }

  condition:
    any of them
}