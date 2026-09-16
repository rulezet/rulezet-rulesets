rule TTP_XOR_WriteProcessMemory_e403 {
  strings:
    $key_e403 = { b3 71 [2] 81 53 [2] 87 66 [2] a9 66 [2] 96 7a }

  condition:
    any of them
}