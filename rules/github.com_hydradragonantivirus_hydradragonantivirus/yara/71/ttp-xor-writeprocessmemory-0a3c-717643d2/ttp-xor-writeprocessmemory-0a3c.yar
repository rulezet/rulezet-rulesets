rule TTP_XOR_WriteProcessMemory_0a3c {
  strings:
    $key_0a3c = { 5d 4e [2] 6f 6c [2] 69 59 [2] 47 59 [2] 78 45 }

  condition:
    any of them
}