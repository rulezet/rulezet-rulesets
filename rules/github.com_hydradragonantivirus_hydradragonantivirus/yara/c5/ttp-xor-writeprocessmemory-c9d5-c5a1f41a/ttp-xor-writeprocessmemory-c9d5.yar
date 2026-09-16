rule TTP_XOR_WriteProcessMemory_c9d5 {
  strings:
    $key_c9d5 = { 9e a7 [2] ac 85 [2] aa b0 [2] 84 b0 [2] bb ac }

  condition:
    any of them
}