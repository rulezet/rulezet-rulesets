rule TTP_XOR_WriteProcessMemory_bd92 {
  strings:
    $key_bd92 = { ea e0 [2] d8 c2 [2] de f7 [2] f0 f7 [2] cf eb }

  condition:
    any of them
}