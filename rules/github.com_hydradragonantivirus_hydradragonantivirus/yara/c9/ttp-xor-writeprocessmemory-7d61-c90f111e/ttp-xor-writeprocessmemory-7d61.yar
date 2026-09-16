rule TTP_XOR_WriteProcessMemory_7d61 {
  strings:
    $key_7d61 = { 2a 13 [2] 18 31 [2] 1e 04 [2] 30 04 [2] 0f 18 }

  condition:
    any of them
}