rule TTP_XOR_WriteProcessMemory_0a37 {
  strings:
    $key_0a37 = { 5d 45 [2] 6f 67 [2] 69 52 [2] 47 52 [2] 78 4e }

  condition:
    any of them
}