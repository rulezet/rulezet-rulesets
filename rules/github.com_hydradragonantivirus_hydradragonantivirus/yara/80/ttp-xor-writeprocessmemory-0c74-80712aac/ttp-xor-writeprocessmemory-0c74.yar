rule TTP_XOR_WriteProcessMemory_0c74 {
  strings:
    $key_0c74 = { 5b 06 [2] 69 24 [2] 6f 11 [2] 41 11 [2] 7e 0d }

  condition:
    any of them
}