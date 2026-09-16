rule TTP_XOR_WriteProcessMemory_9a17 {
  strings:
    $key_9a17 = { cd 65 [2] ff 47 [2] f9 72 [2] d7 72 [2] e8 6e }

  condition:
    any of them
}