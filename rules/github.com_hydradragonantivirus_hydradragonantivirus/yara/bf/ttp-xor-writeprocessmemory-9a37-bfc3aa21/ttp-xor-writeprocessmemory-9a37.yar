rule TTP_XOR_WriteProcessMemory_9a37 {
  strings:
    $key_9a37 = { cd 45 [2] ff 67 [2] f9 52 [2] d7 52 [2] e8 4e }

  condition:
    any of them
}