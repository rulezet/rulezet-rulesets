rule TTP_XOR_WriteProcessMemory_9647 {
  strings:
    $key_9647 = { c1 35 [2] f3 17 [2] f5 22 [2] db 22 [2] e4 3e }

  condition:
    any of them
}