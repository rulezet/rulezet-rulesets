rule TTP_XOR_WriteProcessMemory_86c8 {
  strings:
    $key_86c8 = { d1 ba [2] e3 98 [2] e5 ad [2] cb ad [2] f4 b1 }

  condition:
    any of them
}