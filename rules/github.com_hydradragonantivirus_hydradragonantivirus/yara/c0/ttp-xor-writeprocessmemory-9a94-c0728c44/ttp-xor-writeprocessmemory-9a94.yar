rule TTP_XOR_WriteProcessMemory_9a94 {
  strings:
    $key_9a94 = { cd e6 [2] ff c4 [2] f9 f1 [2] d7 f1 [2] e8 ed }

  condition:
    any of them
}