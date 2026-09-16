rule TTP_XOR_WriteProcessMemory_9bcc {
  strings:
    $key_9bcc = { cc be [2] fe 9c [2] f8 a9 [2] d6 a9 [2] e9 b5 }

  condition:
    any of them
}