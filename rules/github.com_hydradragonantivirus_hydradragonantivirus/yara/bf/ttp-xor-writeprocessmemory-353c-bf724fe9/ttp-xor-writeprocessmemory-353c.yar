rule TTP_XOR_WriteProcessMemory_353c {
  strings:
    $key_353c = { 62 4e [2] 50 6c [2] 56 59 [2] 78 59 [2] 47 45 }

  condition:
    any of them
}