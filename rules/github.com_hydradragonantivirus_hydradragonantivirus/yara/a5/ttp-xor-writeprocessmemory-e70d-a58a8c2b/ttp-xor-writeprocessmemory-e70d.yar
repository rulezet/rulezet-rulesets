rule TTP_XOR_WriteProcessMemory_e70d {
  strings:
    $key_e70d = { b0 7f [2] 82 5d [2] 84 68 [2] aa 68 [2] 95 74 }

  condition:
    any of them
}