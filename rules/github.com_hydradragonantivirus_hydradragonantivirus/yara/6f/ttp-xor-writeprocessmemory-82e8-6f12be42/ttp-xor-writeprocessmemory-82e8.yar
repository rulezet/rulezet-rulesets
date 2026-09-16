rule TTP_XOR_WriteProcessMemory_82e8 {
  strings:
    $key_82e8 = { d5 9a [2] e7 b8 [2] e1 8d [2] cf 8d [2] f0 91 }

  condition:
    any of them
}