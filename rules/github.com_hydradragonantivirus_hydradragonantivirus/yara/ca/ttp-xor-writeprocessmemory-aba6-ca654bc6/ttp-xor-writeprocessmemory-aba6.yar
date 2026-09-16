rule TTP_XOR_WriteProcessMemory_aba6 {
  strings:
    $key_aba6 = { fc d4 [2] ce f6 [2] c8 c3 [2] e6 c3 [2] d9 df }

  condition:
    any of them
}