rule TTP_XOR_WriteProcessMemory_433c {
  strings:
    $key_433c = { 14 4e [2] 26 6c [2] 20 59 [2] 0e 59 [2] 31 45 }

  condition:
    any of them
}