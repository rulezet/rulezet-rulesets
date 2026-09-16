rule TTP_XOR_WriteProcessMemory_9bf4 {
  strings:
    $key_9bf4 = { cc 86 [2] fe a4 [2] f8 91 [2] d6 91 [2] e9 8d }

  condition:
    any of them
}