rule TTP_XOR_WriteProcessMemory_9cb8 {
  strings:
    $key_9cb8 = { cb ca [2] f9 e8 [2] ff dd [2] d1 dd [2] ee c1 }

  condition:
    any of them
}