rule TTP_XOR_WriteProcessMemory_0455 {
  strings:
    $key_0455 = { 53 27 [2] 61 05 [2] 67 30 [2] 49 30 [2] 76 2c }

  condition:
    any of them
}