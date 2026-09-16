rule TTP_XOR_WriteProcessMemory_0a5c {
  strings:
    $key_0a5c = { 5d 2e [2] 6f 0c [2] 69 39 [2] 47 39 [2] 78 25 }

  condition:
    any of them
}