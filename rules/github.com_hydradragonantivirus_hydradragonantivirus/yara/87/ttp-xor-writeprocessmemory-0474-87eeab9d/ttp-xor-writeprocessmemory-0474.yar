rule TTP_XOR_WriteProcessMemory_0474 {
  strings:
    $key_0474 = { 53 06 [2] 61 24 [2] 67 11 [2] 49 11 [2] 76 0d }

  condition:
    any of them
}