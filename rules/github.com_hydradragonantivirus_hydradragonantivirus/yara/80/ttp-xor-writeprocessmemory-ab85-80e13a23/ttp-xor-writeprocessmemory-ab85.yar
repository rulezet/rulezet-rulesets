rule TTP_XOR_WriteProcessMemory_ab85 {
  strings:
    $key_ab85 = { fc f7 [2] ce d5 [2] c8 e0 [2] e6 e0 [2] d9 fc }

  condition:
    any of them
}