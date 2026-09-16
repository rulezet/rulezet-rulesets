rule TTP_XOR_WriteProcessMemory_dd03 {
  strings:
    $key_dd03 = { 8a 71 [2] b8 53 [2] be 66 [2] 90 66 [2] af 7a }

  condition:
    any of them
}