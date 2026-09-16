rule TTP_XOR_WriteProcessMemory_0c04 {
  strings:
    $key_0c04 = { 5b 76 [2] 69 54 [2] 6f 61 [2] 41 61 [2] 7e 7d }

  condition:
    any of them
}