rule TTP_XOR_WriteProcessMemory_9253 {
  strings:
    $key_9253 = { c5 21 [2] f7 03 [2] f1 36 [2] df 36 [2] e0 2a }

  condition:
    any of them
}