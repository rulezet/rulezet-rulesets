rule TTP_XOR_WriteProcessMemory_81a8 {
  strings:
    $key_81a8 = { d6 da [2] e4 f8 [2] e2 cd [2] cc cd [2] f3 d1 }

  condition:
    any of them
}