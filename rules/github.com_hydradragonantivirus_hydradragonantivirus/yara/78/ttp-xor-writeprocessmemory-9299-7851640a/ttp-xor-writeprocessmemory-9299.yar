rule TTP_XOR_WriteProcessMemory_9299 {
  strings:
    $key_9299 = { c5 eb [2] f7 c9 [2] f1 fc [2] df fc [2] e0 e0 }

  condition:
    any of them
}