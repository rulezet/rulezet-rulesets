rule TTP_XOR_WriteProcessMemory_c024 {
  strings:
    $key_c024 = { 97 56 [2] a5 74 [2] a3 41 [2] 8d 41 [2] b2 5d }

  condition:
    any of them
}