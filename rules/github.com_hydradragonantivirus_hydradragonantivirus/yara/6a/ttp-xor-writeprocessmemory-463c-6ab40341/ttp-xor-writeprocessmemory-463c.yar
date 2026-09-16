rule TTP_XOR_WriteProcessMemory_463c {
  strings:
    $key_463c = { 11 4e [2] 23 6c [2] 25 59 [2] 0b 59 [2] 34 45 }

  condition:
    any of them
}