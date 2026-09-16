rule TTP_XOR_WriteProcessMemory_fbc3 {
  strings:
    $key_fbc3 = { ac b1 [2] 9e 93 [2] 98 a6 [2] b6 a6 [2] 89 ba }

  condition:
    any of them
}