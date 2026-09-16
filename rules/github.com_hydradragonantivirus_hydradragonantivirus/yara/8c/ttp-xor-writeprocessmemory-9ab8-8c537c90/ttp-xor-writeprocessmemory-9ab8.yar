rule TTP_XOR_WriteProcessMemory_9ab8 {
  strings:
    $key_9ab8 = { cd ca [2] ff e8 [2] f9 dd [2] d7 dd [2] e8 c1 }

  condition:
    any of them
}