rule TTP_XOR_WriteProcessMemory_9b8d {
  strings:
    $key_9b8d = { cc ff [2] fe dd [2] f8 e8 [2] d6 e8 [2] e9 f4 }

  condition:
    any of them
}