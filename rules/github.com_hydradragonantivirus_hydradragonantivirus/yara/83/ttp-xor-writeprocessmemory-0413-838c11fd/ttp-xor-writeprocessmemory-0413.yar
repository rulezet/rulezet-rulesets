rule TTP_XOR_WriteProcessMemory_0413 {
  strings:
    $key_0413 = { 53 61 [2] 61 43 [2] 67 76 [2] 49 76 [2] 76 6a }

  condition:
    any of them
}