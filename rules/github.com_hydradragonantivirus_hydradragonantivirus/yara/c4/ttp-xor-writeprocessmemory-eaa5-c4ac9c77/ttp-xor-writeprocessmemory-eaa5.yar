rule TTP_XOR_WriteProcessMemory_eaa5 {
  strings:
    $key_eaa5 = { bd d7 [2] 8f f5 [2] 89 c0 [2] a7 c0 [2] 98 dc }

  condition:
    any of them
}