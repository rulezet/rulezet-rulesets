rule TTP_XOR_WriteProcessMemory_9a23 {
  strings:
    $key_9a23 = { cd 51 [2] ff 73 [2] f9 46 [2] d7 46 [2] e8 5a }

  condition:
    any of them
}