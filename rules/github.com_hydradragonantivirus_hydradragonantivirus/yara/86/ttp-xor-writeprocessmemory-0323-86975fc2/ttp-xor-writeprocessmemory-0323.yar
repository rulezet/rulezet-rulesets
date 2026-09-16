rule TTP_XOR_WriteProcessMemory_0323 {
  strings:
    $key_0323 = { 54 51 [2] 66 73 [2] 60 46 [2] 4e 46 [2] 71 5a }

  condition:
    any of them
}