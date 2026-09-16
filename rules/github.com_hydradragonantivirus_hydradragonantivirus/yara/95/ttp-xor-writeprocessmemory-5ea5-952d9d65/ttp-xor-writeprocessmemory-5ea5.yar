rule TTP_XOR_WriteProcessMemory_5ea5 {
  strings:
    $key_5ea5 = { 09 d7 [2] 3b f5 [2] 3d c0 [2] 13 c0 [2] 2c dc }

  condition:
    any of them
}