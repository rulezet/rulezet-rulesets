rule TTP_XOR_WriteProcessMemory_9a64 {
  strings:
    $key_9a64 = { cd 16 [2] ff 34 [2] f9 01 [2] d7 01 [2] e8 1d }

  condition:
    any of them
}