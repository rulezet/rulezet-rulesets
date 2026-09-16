rule TTP_XOR_WriteProcessMemory_443c {
  strings:
    $key_443c = { 13 4e [2] 21 6c [2] 27 59 [2] 09 59 [2] 36 45 }

  condition:
    any of them
}