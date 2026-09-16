rule TTP_XOR_WriteProcessMemory_edd6 {
  strings:
    $key_edd6 = { ba a4 [2] 88 86 [2] 8e b3 [2] a0 b3 [2] 9f af }

  condition:
    any of them
}