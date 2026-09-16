rule TTP_XOR_WriteProcessMemory_d752 {
  strings:
    $key_d752 = { 80 20 [2] b2 02 [2] b4 37 [2] 9a 37 [2] a5 2b }

  condition:
    any of them
}