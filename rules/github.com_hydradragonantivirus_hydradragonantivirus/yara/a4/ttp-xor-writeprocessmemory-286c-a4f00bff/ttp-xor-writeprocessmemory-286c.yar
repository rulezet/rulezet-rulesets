rule TTP_XOR_WriteProcessMemory_286c {
  strings:
    $key_286c = { 7f 1e [2] 4d 3c [2] 4b 09 [2] 65 09 [2] 5a 15 }

  condition:
    any of them
}