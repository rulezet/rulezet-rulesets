rule TTP_XOR_WriteProcessMemory_6cf3 {
  strings:
    $key_6cf3 = { 3b 81 [2] 09 a3 [2] 0f 96 [2] 21 96 [2] 1e 8a }

  condition:
    any of them
}