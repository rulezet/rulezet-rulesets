rule TTP_XOR_WriteProcessMemory_9b9a {
  strings:
    $key_9b9a = { cc e8 [2] fe ca [2] f8 ff [2] d6 ff [2] e9 e3 }

  condition:
    any of them
}