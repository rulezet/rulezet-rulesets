rule TTP_XOR_WriteProcessMemory_c911 {
  strings:
    $key_c911 = { 9e 63 [2] ac 41 [2] aa 74 [2] 84 74 [2] bb 68 }

  condition:
    any of them
}