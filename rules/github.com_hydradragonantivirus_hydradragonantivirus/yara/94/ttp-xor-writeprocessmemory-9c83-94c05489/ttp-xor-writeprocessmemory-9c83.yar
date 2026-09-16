rule TTP_XOR_WriteProcessMemory_9c83 {
  strings:
    $key_9c83 = { cb f1 [2] f9 d3 [2] ff e6 [2] d1 e6 [2] ee fa }

  condition:
    any of them
}