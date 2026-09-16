rule TTP_XOR_WriteProcessMemory_ebe4 {
  strings:
    $key_ebe4 = { bc 96 [2] 8e b4 [2] 88 81 [2] a6 81 [2] 99 9d }

  condition:
    any of them
}