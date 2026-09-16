rule TTP_XOR_WriteProcessMemory_116e {
  strings:
    $key_116e = { 46 1c [2] 74 3e [2] 72 0b [2] 5c 0b [2] 63 17 }

  condition:
    any of them
}