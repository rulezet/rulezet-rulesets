rule TTP_XOR_WriteProcessMemory_c924 {
  strings:
    $key_c924 = { 9e 56 [2] ac 74 [2] aa 41 [2] 84 41 [2] bb 5d }

  condition:
    any of them
}