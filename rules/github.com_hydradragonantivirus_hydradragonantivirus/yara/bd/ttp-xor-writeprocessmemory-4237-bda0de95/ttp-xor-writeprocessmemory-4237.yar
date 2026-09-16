rule TTP_XOR_WriteProcessMemory_4237 {
  strings:
    $key_4237 = { 15 45 [2] 27 67 [2] 21 52 [2] 0f 52 [2] 30 4e }

  condition:
    any of them
}