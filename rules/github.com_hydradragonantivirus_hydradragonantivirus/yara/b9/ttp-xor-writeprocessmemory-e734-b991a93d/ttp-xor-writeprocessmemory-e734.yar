rule TTP_XOR_WriteProcessMemory_e734 {
  strings:
    $key_e734 = { b0 46 [2] 82 64 [2] 84 51 [2] aa 51 [2] 95 4d }

  condition:
    any of them
}