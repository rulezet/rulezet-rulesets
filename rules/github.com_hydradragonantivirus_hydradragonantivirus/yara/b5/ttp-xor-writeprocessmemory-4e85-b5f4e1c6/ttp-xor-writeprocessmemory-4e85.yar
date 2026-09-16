rule TTP_XOR_WriteProcessMemory_4e85 {
  strings:
    $key_4e85 = { 19 f7 [2] 2b d5 [2] 2d e0 [2] 03 e0 [2] 3c fc }

  condition:
    any of them
}