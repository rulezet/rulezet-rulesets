rule TTP_XOR_WriteProcessMemory_0453 {
  strings:
    $key_0453 = { 53 21 [2] 61 03 [2] 67 36 [2] 49 36 [2] 76 2a }

  condition:
    any of them
}