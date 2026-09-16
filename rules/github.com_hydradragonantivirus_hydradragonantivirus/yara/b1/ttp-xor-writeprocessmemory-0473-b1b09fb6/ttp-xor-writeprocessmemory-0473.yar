rule TTP_XOR_WriteProcessMemory_0473 {
  strings:
    $key_0473 = { 53 01 [2] 61 23 [2] 67 16 [2] 49 16 [2] 76 0a }

  condition:
    any of them
}