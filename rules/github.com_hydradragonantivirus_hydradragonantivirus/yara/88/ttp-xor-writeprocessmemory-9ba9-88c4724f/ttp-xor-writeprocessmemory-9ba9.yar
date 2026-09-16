rule TTP_XOR_WriteProcessMemory_9ba9 {
  strings:
    $key_9ba9 = { cc db [2] fe f9 [2] f8 cc [2] d6 cc [2] e9 d0 }

  condition:
    any of them
}