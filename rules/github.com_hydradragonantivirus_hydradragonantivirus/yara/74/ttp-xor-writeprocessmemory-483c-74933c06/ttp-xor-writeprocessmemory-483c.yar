rule TTP_XOR_WriteProcessMemory_483c {
  strings:
    $key_483c = { 1f 4e [2] 2d 6c [2] 2b 59 [2] 05 59 [2] 3a 45 }

  condition:
    any of them
}