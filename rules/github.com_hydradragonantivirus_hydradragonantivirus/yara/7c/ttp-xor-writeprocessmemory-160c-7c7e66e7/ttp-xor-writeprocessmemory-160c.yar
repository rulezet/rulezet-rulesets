rule TTP_XOR_WriteProcessMemory_160c {
  strings:
    $key_160c = { 41 7e [2] 73 5c [2] 75 69 [2] 5b 69 [2] 64 75 }

  condition:
    any of them
}