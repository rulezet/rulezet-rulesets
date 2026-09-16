rule TTP_XOR_WriteProcessMemory_ab37 {
  strings:
    $key_ab37 = { fc 45 [2] ce 67 [2] c8 52 [2] e6 52 [2] d9 4e }

  condition:
    any of them
}