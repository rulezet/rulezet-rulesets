rule TTP_XOR_WriteProcessMemory_c901 {
  strings:
    $key_c901 = { 9e 73 [2] ac 51 [2] aa 64 [2] 84 64 [2] bb 78 }

  condition:
    any of them
}