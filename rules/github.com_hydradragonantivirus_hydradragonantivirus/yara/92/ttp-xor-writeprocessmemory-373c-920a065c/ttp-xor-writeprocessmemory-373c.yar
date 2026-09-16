rule TTP_XOR_WriteProcessMemory_373c {
  strings:
    $key_373c = { 60 4e [2] 52 6c [2] 54 59 [2] 7a 59 [2] 45 45 }

  condition:
    any of them
}