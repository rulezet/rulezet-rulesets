rule TTP_XOR_WriteProcessMemory_9be3 {
  strings:
    $key_9be3 = { cc 91 [2] fe b3 [2] f8 86 [2] d6 86 [2] e9 9a }

  condition:
    any of them
}