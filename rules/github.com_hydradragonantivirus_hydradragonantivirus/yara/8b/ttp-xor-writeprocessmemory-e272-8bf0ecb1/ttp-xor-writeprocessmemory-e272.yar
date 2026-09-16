rule TTP_XOR_WriteProcessMemory_e272 {
  strings:
    $key_e272 = { b5 00 [2] 87 22 [2] 81 17 [2] af 17 [2] 90 0b }

  condition:
    any of them
}