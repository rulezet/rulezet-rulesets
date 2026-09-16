rule TTP_XOR_WriteProcessMemory_7ea3 {
  strings:
    $key_7ea3 = { 29 d1 [2] 1b f3 [2] 1d c6 [2] 33 c6 [2] 0c da }

  condition:
    any of them
}