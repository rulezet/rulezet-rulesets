rule TTP_XOR_WriteProcessMemory_9be9 {
  strings:
    $key_9be9 = { cc 9b [2] fe b9 [2] f8 8c [2] d6 8c [2] e9 90 }

  condition:
    any of them
}