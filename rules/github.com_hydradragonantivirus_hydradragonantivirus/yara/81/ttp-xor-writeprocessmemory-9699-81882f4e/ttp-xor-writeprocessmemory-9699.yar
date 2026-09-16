rule TTP_XOR_WriteProcessMemory_9699 {
  strings:
    $key_9699 = { c1 eb [2] f3 c9 [2] f5 fc [2] db fc [2] e4 e0 }

  condition:
    any of them
}