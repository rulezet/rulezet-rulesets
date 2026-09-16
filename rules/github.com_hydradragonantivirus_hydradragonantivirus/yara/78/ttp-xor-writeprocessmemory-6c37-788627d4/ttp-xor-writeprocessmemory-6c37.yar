rule TTP_XOR_WriteProcessMemory_6c37 {
  strings:
    $key_6c37 = { 3b 45 [2] 09 67 [2] 0f 52 [2] 21 52 [2] 1e 4e }

  condition:
    any of them
}