rule TTP_XOR_WriteProcessMemory_9799 {
  strings:
    $key_9799 = { c0 eb [2] f2 c9 [2] f4 fc [2] da fc [2] e5 e0 }

  condition:
    any of them
}