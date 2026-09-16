rule TTP_XOR_WriteProcessMemory_9a35 {
  strings:
    $key_9a35 = { cd 47 [2] ff 65 [2] f9 50 [2] d7 50 [2] e8 4c }

  condition:
    any of them
}