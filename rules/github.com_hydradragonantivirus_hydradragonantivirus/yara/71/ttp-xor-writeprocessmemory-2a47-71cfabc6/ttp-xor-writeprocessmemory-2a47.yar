rule TTP_XOR_WriteProcessMemory_2a47 {
  strings:
    $key_2a47 = { 7d 35 [2] 4f 17 [2] 49 22 [2] 67 22 [2] 58 3e }

  condition:
    any of them
}