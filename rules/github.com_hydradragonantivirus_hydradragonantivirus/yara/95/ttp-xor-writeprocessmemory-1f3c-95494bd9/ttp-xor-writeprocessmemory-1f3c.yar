rule TTP_XOR_WriteProcessMemory_1f3c {
  strings:
    $key_1f3c = { 48 4e [2] 7a 6c [2] 7c 59 [2] 52 59 [2] 6d 45 }

  condition:
    any of them
}