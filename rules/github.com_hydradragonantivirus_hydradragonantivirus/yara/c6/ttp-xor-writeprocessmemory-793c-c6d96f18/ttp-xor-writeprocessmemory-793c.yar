rule TTP_XOR_WriteProcessMemory_793c {
  strings:
    $key_793c = { 2e 4e [2] 1c 6c [2] 1a 59 [2] 34 59 [2] 0b 45 }

  condition:
    any of them
}