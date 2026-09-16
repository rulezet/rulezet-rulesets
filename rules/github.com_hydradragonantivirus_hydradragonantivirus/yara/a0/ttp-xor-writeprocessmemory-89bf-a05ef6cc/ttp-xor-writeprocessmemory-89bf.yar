rule TTP_XOR_WriteProcessMemory_89bf {
  strings:
    $key_89bf = { de cd [2] ec ef [2] ea da [2] c4 da [2] fb c6 }

  condition:
    any of them
}