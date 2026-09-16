rule TTP_XOR_WriteProcessMemory_7d11 {
  strings:
    $key_7d11 = { 2a 63 [2] 18 41 [2] 1e 74 [2] 30 74 [2] 0f 68 }

  condition:
    any of them
}