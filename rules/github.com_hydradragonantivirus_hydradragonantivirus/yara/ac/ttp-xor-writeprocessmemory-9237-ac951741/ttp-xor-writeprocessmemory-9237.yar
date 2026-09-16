rule TTP_XOR_WriteProcessMemory_9237 {
  strings:
    $key_9237 = { c5 45 [2] f7 67 [2] f1 52 [2] df 52 [2] e0 4e }

  condition:
    any of them
}