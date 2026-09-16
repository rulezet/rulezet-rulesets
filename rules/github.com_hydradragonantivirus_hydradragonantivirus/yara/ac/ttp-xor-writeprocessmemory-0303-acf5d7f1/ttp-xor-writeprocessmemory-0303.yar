rule TTP_XOR_WriteProcessMemory_0303 {
  strings:
    $key_0303 = { 54 71 [2] 66 53 [2] 60 66 [2] 4e 66 [2] 71 7a }

  condition:
    any of them
}