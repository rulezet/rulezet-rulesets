rule TTP_XOR_WriteProcessMemory_7e85 {
  strings:
    $key_7e85 = { 29 f7 [2] 1b d5 [2] 1d e0 [2] 33 e0 [2] 0c fc }

  condition:
    any of them
}