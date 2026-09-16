rule TTP_XOR_WriteProcessMemory_7ea5 {
  strings:
    $key_7ea5 = { 29 d7 [2] 1b f5 [2] 1d c0 [2] 33 c0 [2] 0c dc }

  condition:
    any of them
}