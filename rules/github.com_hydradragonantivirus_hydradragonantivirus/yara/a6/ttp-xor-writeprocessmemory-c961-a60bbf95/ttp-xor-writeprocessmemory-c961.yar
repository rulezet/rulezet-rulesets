rule TTP_XOR_WriteProcessMemory_c961 {
  strings:
    $key_c961 = { 9e 13 [2] ac 31 [2] aa 04 [2] 84 04 [2] bb 18 }

  condition:
    any of them
}