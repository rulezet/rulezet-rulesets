rule TTP_XOR_WriteProcessMemory_ddf6 {
  strings:
    $key_ddf6 = { 8a 84 [2] b8 a6 [2] be 93 [2] 90 93 [2] af 8f }

  condition:
    any of them
}