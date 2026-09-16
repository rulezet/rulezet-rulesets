rule TTP_XOR_WriteProcessMemory_0486 {
  strings:
    $key_0486 = { 53 f4 [2] 61 d6 [2] 67 e3 [2] 49 e3 [2] 76 ff }

  condition:
    any of them
}