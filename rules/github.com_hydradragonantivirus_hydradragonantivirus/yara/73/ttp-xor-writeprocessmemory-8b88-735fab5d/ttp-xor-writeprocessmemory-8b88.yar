rule TTP_XOR_WriteProcessMemory_8b88 {
  strings:
    $key_8b88 = { dc fa [2] ee d8 [2] e8 ed [2] c6 ed [2] f9 f1 }

  condition:
    any of them
}