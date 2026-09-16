rule TTP_XOR_WriteProcessMemory_d104 {
  strings:
    $key_d104 = { 86 76 [2] b4 54 [2] b2 61 [2] 9c 61 [2] a3 7d }

  condition:
    any of them
}