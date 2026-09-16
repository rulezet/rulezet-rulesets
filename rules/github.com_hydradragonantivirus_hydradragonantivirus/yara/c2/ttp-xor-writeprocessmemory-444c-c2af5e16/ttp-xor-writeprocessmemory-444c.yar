rule TTP_XOR_WriteProcessMemory_444c {
  strings:
    $key_444c = { 13 3e [2] 21 1c [2] 27 29 [2] 09 29 [2] 36 35 }

  condition:
    any of them
}