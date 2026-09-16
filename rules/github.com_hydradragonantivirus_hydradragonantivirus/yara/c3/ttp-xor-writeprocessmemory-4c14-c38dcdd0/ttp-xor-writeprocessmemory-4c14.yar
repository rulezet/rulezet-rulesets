rule TTP_XOR_WriteProcessMemory_4c14 {
  strings:
    $key_4c14 = { 1b 66 [2] 29 44 [2] 2f 71 [2] 01 71 [2] 3e 6d }

  condition:
    any of them
}