rule TTP_XOR_WriteProcessMemory_9adf {
  strings:
    $key_9adf = { cd ad [2] ff 8f [2] f9 ba [2] d7 ba [2] e8 a6 }

  condition:
    any of them
}