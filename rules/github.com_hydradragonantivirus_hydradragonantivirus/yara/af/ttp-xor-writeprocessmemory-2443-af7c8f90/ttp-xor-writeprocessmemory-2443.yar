rule TTP_XOR_WriteProcessMemory_2443 {
  strings:
    $key_2443 = { 73 31 [2] 41 13 [2] 47 26 [2] 69 26 [2] 56 3a }

  condition:
    any of them
}