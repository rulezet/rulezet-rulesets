rule TTP_XOR_WriteProcessMemory_326c {
  strings:
    $key_326c = { 65 1e [2] 57 3c [2] 51 09 [2] 7f 09 [2] 40 15 }

  condition:
    any of them
}