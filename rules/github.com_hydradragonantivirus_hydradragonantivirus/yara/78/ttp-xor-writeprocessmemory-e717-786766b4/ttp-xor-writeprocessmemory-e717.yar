rule TTP_XOR_WriteProcessMemory_e717 {
  strings:
    $key_e717 = { b0 65 [2] 82 47 [2] 84 72 [2] aa 72 [2] 95 6e }

  condition:
    any of them
}