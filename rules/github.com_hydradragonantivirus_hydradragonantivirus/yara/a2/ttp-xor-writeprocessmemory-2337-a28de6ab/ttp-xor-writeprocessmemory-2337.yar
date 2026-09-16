rule TTP_XOR_WriteProcessMemory_2337 {
  strings:
    $key_2337 = { 74 45 [2] 46 67 [2] 40 52 [2] 6e 52 [2] 51 4e }

  condition:
    any of them
}