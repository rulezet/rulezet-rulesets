rule TTP_XOR_WriteProcessMemory_046c {
  strings:
    $key_046c = { 53 1e [2] 61 3c [2] 67 09 [2] 49 09 [2] 76 15 }

  condition:
    any of them
}