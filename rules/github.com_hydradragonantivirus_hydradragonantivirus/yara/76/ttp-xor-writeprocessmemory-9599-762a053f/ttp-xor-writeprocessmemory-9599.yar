rule TTP_XOR_WriteProcessMemory_9599 {
  strings:
    $key_9599 = { c2 eb [2] f0 c9 [2] f6 fc [2] d8 fc [2] e7 e0 }

  condition:
    any of them
}