rule TTP_XOR_WriteProcessMemory_e1c8 {
  strings:
    $key_e1c8 = { b6 ba [2] 84 98 [2] 82 ad [2] ac ad [2] 93 b1 }

  condition:
    any of them
}