rule TTP_XOR_WriteProcessMemory_aba4 {
  strings:
    $key_aba4 = { fc d6 [2] ce f4 [2] c8 c1 [2] e6 c1 [2] d9 dd }

  condition:
    any of them
}