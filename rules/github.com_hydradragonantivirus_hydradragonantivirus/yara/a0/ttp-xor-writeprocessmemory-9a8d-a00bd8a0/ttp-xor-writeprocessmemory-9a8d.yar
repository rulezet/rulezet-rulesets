rule TTP_XOR_WriteProcessMemory_9a8d {
  strings:
    $key_9a8d = { cd ff [2] ff dd [2] f9 e8 [2] d7 e8 [2] e8 f4 }

  condition:
    any of them
}