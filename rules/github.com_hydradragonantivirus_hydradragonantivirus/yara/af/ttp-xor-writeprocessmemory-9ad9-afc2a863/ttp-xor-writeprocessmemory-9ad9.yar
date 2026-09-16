rule TTP_XOR_WriteProcessMemory_9ad9 {
  strings:
    $key_9ad9 = { cd ab [2] ff 89 [2] f9 bc [2] d7 bc [2] e8 a0 }

  condition:
    any of them
}