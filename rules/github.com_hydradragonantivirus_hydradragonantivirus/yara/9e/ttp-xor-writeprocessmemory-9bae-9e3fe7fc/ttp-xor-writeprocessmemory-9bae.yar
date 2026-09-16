rule TTP_XOR_WriteProcessMemory_9bae {
  strings:
    $key_9bae = { cc dc [2] fe fe [2] f8 cb [2] d6 cb [2] e9 d7 }

  condition:
    any of them
}