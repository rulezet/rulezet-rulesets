rule TTP_XOR_WriteProcessMemory_1186 {
  strings:
    $key_1186 = { 46 f4 [2] 74 d6 [2] 72 e3 [2] 5c e3 [2] 63 ff }

  condition:
    any of them
}