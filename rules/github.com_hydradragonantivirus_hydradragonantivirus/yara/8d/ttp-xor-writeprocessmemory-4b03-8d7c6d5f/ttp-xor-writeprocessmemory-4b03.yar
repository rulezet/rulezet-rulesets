rule TTP_XOR_WriteProcessMemory_4b03 {
  strings:
    $key_4b03 = { 1c 71 [2] 2e 53 [2] 28 66 [2] 06 66 [2] 39 7a }

  condition:
    any of them
}