rule TTP_XOR_WriteProcessMemory_9a47 {
  strings:
    $key_9a47 = { cd 35 [2] ff 17 [2] f9 22 [2] d7 22 [2] e8 3e }

  condition:
    any of them
}