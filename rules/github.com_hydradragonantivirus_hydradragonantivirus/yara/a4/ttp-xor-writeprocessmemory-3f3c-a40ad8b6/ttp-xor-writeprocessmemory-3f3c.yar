rule TTP_XOR_WriteProcessMemory_3f3c {
  strings:
    $key_3f3c = { 68 4e [2] 5a 6c [2] 5c 59 [2] 72 59 [2] 4d 45 }

  condition:
    any of them
}