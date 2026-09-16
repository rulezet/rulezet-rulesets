rule TTP_XOR_WriteProcessMemory_442c {
  strings:
    $key_442c = { 13 5e [2] 21 7c [2] 27 49 [2] 09 49 [2] 36 55 }

  condition:
    any of them
}