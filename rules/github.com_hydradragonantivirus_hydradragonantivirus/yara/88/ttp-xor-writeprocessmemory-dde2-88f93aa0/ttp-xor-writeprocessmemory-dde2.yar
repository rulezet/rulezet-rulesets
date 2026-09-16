rule TTP_XOR_WriteProcessMemory_dde2 {
  strings:
    $key_dde2 = { 8a 90 [2] b8 b2 [2] be 87 [2] 90 87 [2] af 9b }

  condition:
    any of them
}