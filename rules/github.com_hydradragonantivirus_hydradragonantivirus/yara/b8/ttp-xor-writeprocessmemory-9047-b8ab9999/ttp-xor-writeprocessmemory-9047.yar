rule TTP_XOR_WriteProcessMemory_9047 {
  strings:
    $key_9047 = { c7 35 [2] f5 17 [2] f3 22 [2] dd 22 [2] e2 3e }

  condition:
    any of them
}