rule TTP_XOR_WriteProcessMemory_7c14 {
  strings:
    $key_7c14 = { 2b 66 [2] 19 44 [2] 1f 71 [2] 31 71 [2] 0e 6d }

  condition:
    any of them
}