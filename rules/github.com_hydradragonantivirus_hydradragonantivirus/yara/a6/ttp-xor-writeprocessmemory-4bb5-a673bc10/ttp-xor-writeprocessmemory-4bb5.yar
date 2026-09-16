rule TTP_XOR_WriteProcessMemory_4bb5 {
  strings:
    $key_4bb5 = { 1c c7 [2] 2e e5 [2] 28 d0 [2] 06 d0 [2] 39 cc }

  condition:
    any of them
}