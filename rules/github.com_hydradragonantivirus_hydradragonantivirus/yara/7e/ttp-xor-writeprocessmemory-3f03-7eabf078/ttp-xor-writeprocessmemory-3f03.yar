rule TTP_XOR_WriteProcessMemory_3f03 {
  strings:
    $key_3f03 = { 68 71 [2] 5a 53 [2] 5c 66 [2] 72 66 [2] 4d 7a }

  condition:
    any of them
}