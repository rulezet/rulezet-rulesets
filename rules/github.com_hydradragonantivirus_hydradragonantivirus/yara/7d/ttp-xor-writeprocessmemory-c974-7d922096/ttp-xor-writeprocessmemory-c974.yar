rule TTP_XOR_WriteProcessMemory_c974 {
  strings:
    $key_c974 = { 9e 06 [2] ac 24 [2] aa 11 [2] 84 11 [2] bb 0d }

  condition:
    any of them
}