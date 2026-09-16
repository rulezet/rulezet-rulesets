rule TTP_XOR_WriteProcessMemory_213c {
  strings:
    $key_213c = { 76 4e [2] 44 6c [2] 42 59 [2] 6c 59 [2] 53 45 }

  condition:
    any of them
}