rule TTP_XOR_WriteProcessMemory_c034 {
  strings:
    $key_c034 = { 97 46 [2] a5 64 [2] a3 51 [2] 8d 51 [2] b2 4d }

  condition:
    any of them
}