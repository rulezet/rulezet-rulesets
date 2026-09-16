rule TTP_XOR_WriteProcessMemory_0471 {
  strings:
    $key_0471 = { 53 03 [2] 61 21 [2] 67 14 [2] 49 14 [2] 76 08 }

  condition:
    any of them
}