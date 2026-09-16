rule TTP_XOR_WriteProcessMemory_9a24 {
  strings:
    $key_9a24 = { cd 56 [2] ff 74 [2] f9 41 [2] d7 41 [2] e8 5d }

  condition:
    any of them
}