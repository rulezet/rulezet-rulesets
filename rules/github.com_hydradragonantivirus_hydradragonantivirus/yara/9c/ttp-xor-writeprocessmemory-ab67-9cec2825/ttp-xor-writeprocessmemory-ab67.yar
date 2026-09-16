rule TTP_XOR_WriteProcessMemory_ab67 {
  strings:
    $key_ab67 = { fc 15 [2] ce 37 [2] c8 02 [2] e6 02 [2] d9 1e }

  condition:
    any of them
}