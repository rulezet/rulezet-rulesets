rule TTP_XOR_WriteProcessMemory_9cb4 {
  strings:
    $key_9cb4 = { cb c6 [2] f9 e4 [2] ff d1 [2] d1 d1 [2] ee cd }

  condition:
    any of them
}