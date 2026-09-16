rule TTP_XOR_WriteProcessMemory_0437 {
  strings:
    $key_0437 = { 53 45 [2] 61 67 [2] 67 52 [2] 49 52 [2] 76 4e }

  condition:
    any of them
}