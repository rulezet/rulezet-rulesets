rule TTP_XOR_WriteProcessMemory_8eb9 {
  strings:
    $key_8eb9 = { d9 cb [2] eb e9 [2] ed dc [2] c3 dc [2] fc c0 }

  condition:
    any of them
}