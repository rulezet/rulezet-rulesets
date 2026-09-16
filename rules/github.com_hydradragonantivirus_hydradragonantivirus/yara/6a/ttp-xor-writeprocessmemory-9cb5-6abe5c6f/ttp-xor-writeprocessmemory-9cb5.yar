rule TTP_XOR_WriteProcessMemory_9cb5 {
  strings:
    $key_9cb5 = { cb c7 [2] f9 e5 [2] ff d0 [2] d1 d0 [2] ee cc }

  condition:
    any of them
}