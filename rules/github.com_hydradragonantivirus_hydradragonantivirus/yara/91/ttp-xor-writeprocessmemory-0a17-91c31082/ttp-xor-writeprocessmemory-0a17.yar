rule TTP_XOR_WriteProcessMemory_0a17 {
  strings:
    $key_0a17 = { 5d 65 [2] 6f 47 [2] 69 72 [2] 47 72 [2] 78 6e }

  condition:
    any of them
}