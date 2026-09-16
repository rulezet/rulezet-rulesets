rule TTP_XOR_WriteProcessMemory_9a97 {
  strings:
    $key_9a97 = { cd e5 [2] ff c7 [2] f9 f2 [2] d7 f2 [2] e8 ee }

  condition:
    any of them
}