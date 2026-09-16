rule TTP_XOR_WriteProcessMemory_7914 {
  strings:
    $key_7914 = { 2e 66 [2] 1c 44 [2] 1a 71 [2] 34 71 [2] 0b 6d }

  condition:
    any of them
}