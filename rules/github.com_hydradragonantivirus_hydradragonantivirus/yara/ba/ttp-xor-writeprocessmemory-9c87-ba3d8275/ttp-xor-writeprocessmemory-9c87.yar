rule TTP_XOR_WriteProcessMemory_9c87 {
  strings:
    $key_9c87 = { cb f5 [2] f9 d7 [2] ff e2 [2] d1 e2 [2] ee fe }

  condition:
    any of them
}