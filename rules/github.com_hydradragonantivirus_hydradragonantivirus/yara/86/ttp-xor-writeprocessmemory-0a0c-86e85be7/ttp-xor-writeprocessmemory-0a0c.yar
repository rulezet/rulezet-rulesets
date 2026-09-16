rule TTP_XOR_WriteProcessMemory_0a0c {
  strings:
    $key_0a0c = { 5d 7e [2] 6f 5c [2] 69 69 [2] 47 69 [2] 78 75 }

  condition:
    any of them
}