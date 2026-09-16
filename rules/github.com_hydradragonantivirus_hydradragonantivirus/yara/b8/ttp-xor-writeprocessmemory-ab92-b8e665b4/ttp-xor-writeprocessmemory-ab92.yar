rule TTP_XOR_WriteProcessMemory_ab92 {
  strings:
    $key_ab92 = { fc e0 [2] ce c2 [2] c8 f7 [2] e6 f7 [2] d9 eb }

  condition:
    any of them
}