rule TTP_XOR_WriteProcessMemory_9393 {
  strings:
    $key_9393 = { c4 e1 [2] f6 c3 [2] f0 f6 [2] de f6 [2] e1 ea }

  condition:
    any of them
}