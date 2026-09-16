rule TTP_XOR_WriteProcessMemory_9ca1 {
  strings:
    $key_9ca1 = { cb d3 [2] f9 f1 [2] ff c4 [2] d1 c4 [2] ee d8 }

  condition:
    any of them
}