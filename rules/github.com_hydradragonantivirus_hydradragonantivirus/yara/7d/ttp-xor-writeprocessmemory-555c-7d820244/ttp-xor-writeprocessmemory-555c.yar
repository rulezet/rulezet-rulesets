rule TTP_XOR_WriteProcessMemory_555c {
  strings:
    $key_555c = { 02 2e [2] 30 0c [2] 36 39 [2] 18 39 [2] 27 25 }

  condition:
    any of them
}