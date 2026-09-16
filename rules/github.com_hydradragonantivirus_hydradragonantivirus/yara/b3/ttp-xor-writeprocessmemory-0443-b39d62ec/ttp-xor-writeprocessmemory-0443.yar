rule TTP_XOR_WriteProcessMemory_0443 {
  strings:
    $key_0443 = { 53 31 [2] 61 13 [2] 67 26 [2] 49 26 [2] 76 3a }

  condition:
    any of them
}