rule TTP_XOR_WriteProcessMemory_9499 {
  strings:
    $key_9499 = { c3 eb [2] f1 c9 [2] f7 fc [2] d9 fc [2] e6 e0 }

  condition:
    any of them
}