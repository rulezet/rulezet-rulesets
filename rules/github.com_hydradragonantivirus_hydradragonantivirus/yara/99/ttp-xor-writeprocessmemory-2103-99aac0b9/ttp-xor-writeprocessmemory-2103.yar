rule TTP_XOR_WriteProcessMemory_2103 {
  strings:
    $key_2103 = { 76 71 [2] 44 53 [2] 42 66 [2] 6c 66 [2] 53 7a }

  condition:
    any of them
}