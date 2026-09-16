rule TTP_XOR_WriteProcessMemory_9a53 {
  strings:
    $key_9a53 = { cd 21 [2] ff 03 [2] f9 36 [2] d7 36 [2] e8 2a }

  condition:
    any of them
}