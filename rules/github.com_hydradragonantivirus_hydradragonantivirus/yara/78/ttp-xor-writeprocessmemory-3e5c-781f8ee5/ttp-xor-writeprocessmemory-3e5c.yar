rule TTP_XOR_WriteProcessMemory_3e5c {
  strings:
    $key_3e5c = { 69 2e [2] 5b 0c [2] 5d 39 [2] 73 39 [2] 4c 25 }

  condition:
    any of them
}