rule TTP_XOR_WriteProcessMemory_ddc0 {
  strings:
    $key_ddc0 = { 8a b2 [2] b8 90 [2] be a5 [2] 90 a5 [2] af b9 }

  condition:
    any of them
}