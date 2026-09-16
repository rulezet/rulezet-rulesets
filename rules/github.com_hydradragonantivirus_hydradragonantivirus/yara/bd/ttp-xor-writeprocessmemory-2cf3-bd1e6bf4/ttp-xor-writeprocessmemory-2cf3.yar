rule TTP_XOR_WriteProcessMemory_2cf3 {
  strings:
    $key_2cf3 = { 7b 81 [2] 49 a3 [2] 4f 96 [2] 61 96 [2] 5e 8a }

  condition:
    any of them
}