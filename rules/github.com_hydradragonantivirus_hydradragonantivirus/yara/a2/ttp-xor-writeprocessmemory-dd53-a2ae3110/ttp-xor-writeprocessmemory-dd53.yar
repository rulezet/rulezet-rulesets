rule TTP_XOR_WriteProcessMemory_dd53 {
  strings:
    $key_dd53 = { 8a 21 [2] b8 03 [2] be 36 [2] 90 36 [2] af 2a }

  condition:
    any of them
}