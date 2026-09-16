rule TTP_XOR_WriteProcessMemory_e061 {
  strings:
    $key_e061 = { b7 13 [2] 85 31 [2] 83 04 [2] ad 04 [2] 92 18 }

  condition:
    any of them
}