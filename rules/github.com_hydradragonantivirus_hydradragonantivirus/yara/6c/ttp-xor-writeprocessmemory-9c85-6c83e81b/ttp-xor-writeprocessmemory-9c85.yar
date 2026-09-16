rule TTP_XOR_WriteProcessMemory_9c85 {
  strings:
    $key_9c85 = { cb f7 [2] f9 d5 [2] ff e0 [2] d1 e0 [2] ee fc }

  condition:
    any of them
}