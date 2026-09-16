rule TTP_XOR_WriteProcessMemory_513c {
  strings:
    $key_513c = { 06 4e [2] 34 6c [2] 32 59 [2] 1c 59 [2] 23 45 }

  condition:
    any of them
}