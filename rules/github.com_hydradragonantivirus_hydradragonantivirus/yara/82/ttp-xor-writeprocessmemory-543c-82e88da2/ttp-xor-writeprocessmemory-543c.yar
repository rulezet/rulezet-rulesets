rule TTP_XOR_WriteProcessMemory_543c {
  strings:
    $key_543c = { 03 4e [2] 31 6c [2] 37 59 [2] 19 59 [2] 26 45 }

  condition:
    any of them
}