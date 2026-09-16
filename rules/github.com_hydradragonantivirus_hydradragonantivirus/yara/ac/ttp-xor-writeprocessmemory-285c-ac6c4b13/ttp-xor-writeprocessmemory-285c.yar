rule TTP_XOR_WriteProcessMemory_285c {
  strings:
    $key_285c = { 7f 2e [2] 4d 0c [2] 4b 39 [2] 65 39 [2] 5a 25 }

  condition:
    any of them
}