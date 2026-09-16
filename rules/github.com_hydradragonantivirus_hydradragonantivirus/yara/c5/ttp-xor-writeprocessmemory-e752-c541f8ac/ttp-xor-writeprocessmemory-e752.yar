rule TTP_XOR_WriteProcessMemory_e752 {
  strings:
    $key_e752 = { b0 20 [2] 82 02 [2] 84 37 [2] aa 37 [2] 95 2b }

  condition:
    any of them
}