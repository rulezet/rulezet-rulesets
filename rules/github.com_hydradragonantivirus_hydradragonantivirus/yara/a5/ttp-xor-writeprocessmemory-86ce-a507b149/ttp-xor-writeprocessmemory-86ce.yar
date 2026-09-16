rule TTP_XOR_WriteProcessMemory_86ce {
  strings:
    $key_86ce = { d1 bc [2] e3 9e [2] e5 ab [2] cb ab [2] f4 b7 }

  condition:
    any of them
}