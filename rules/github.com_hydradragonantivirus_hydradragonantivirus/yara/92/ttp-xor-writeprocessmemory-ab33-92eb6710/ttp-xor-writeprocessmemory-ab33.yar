rule TTP_XOR_WriteProcessMemory_ab33 {
  strings:
    $key_ab33 = { fc 41 [2] ce 63 [2] c8 56 [2] e6 56 [2] d9 4a }

  condition:
    any of them
}