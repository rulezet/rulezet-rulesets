rule TTP_XOR_WriteProcessMemory_ab73 {
  strings:
    $key_ab73 = { fc 01 [2] ce 23 [2] c8 16 [2] e6 16 [2] d9 0a }

  condition:
    any of them
}