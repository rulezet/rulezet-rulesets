rule TTP_XOR_WriteProcessMemory_ab53 {
  strings:
    $key_ab53 = { fc 21 [2] ce 03 [2] c8 36 [2] e6 36 [2] d9 2a }

  condition:
    any of them
}