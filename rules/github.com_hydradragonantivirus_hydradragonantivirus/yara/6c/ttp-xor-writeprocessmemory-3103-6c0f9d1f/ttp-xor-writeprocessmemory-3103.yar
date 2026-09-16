rule TTP_XOR_WriteProcessMemory_3103 {
  strings:
    $key_3103 = { 66 71 [2] 54 53 [2] 52 66 [2] 7c 66 [2] 43 7a }

  condition:
    any of them
}