rule TTP_XOR_WriteProcessMemory_0637 {
  strings:
    $key_0637 = { 51 45 [2] 63 67 [2] 65 52 [2] 4b 52 [2] 74 4e }

  condition:
    any of them
}