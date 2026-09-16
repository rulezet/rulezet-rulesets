rule TTP_XOR_WriteProcessMemory_e724 {
  strings:
    $key_e724 = { b0 56 [2] 82 74 [2] 84 41 [2] aa 41 [2] 95 5d }

  condition:
    any of them
}