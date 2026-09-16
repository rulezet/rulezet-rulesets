rule TTP_XOR_WriteProcessMemory_0a13 {
  strings:
    $key_0a13 = { 5d 61 [2] 6f 43 [2] 69 76 [2] 47 76 [2] 78 6a }

  condition:
    any of them
}