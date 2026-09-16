rule TTP_XOR_WriteProcessMemory_c914 {
  strings:
    $key_c914 = { 9e 66 [2] ac 44 [2] aa 71 [2] 84 71 [2] bb 6d }

  condition:
    any of them
}