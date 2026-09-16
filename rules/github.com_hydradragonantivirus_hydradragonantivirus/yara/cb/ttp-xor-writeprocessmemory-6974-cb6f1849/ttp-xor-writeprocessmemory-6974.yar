rule TTP_XOR_WriteProcessMemory_6974 {
  strings:
    $key_6974 = { 3e 06 [2] 0c 24 [2] 0a 11 [2] 24 11 [2] 1b 0d }

  condition:
    any of them
}