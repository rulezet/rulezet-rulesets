rule TTP_XOR_WriteProcessMemory_8db5 {
  strings:
    $key_8db5 = { da c7 [2] e8 e5 [2] ee d0 [2] c0 d0 [2] ff cc }

  condition:
    any of them
}