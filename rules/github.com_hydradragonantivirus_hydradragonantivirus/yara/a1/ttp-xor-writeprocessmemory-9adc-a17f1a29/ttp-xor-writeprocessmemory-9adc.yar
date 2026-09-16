rule TTP_XOR_WriteProcessMemory_9adc {
  strings:
    $key_9adc = { cd ae [2] ff 8c [2] f9 b9 [2] d7 b9 [2] e8 a5 }

  condition:
    any of them
}