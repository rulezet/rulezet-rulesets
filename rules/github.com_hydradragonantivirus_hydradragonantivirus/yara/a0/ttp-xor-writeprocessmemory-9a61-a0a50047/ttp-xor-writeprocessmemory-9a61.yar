rule TTP_XOR_WriteProcessMemory_9a61 {
  strings:
    $key_9a61 = { cd 13 [2] ff 31 [2] f9 04 [2] d7 04 [2] e8 18 }

  condition:
    any of them
}