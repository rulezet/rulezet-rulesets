rule TTP_XOR_WriteProcessMemory_d164 {
  strings:
    $key_d164 = { 86 16 [2] b4 34 [2] b2 01 [2] 9c 01 [2] a3 1d }

  condition:
    any of them
}