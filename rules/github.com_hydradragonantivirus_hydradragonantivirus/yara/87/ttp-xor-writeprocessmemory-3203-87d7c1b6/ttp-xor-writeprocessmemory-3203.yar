rule TTP_XOR_WriteProcessMemory_3203 {
  strings:
    $key_3203 = { 65 71 [2] 57 53 [2] 51 66 [2] 7f 66 [2] 40 7a }

  condition:
    any of them
}