rule TTP_XOR_WriteProcessMemory_674c {
  strings:
    $key_674c = { 30 3e [2] 02 1c [2] 04 29 [2] 2a 29 [2] 15 35 }

  condition:
    any of them
}