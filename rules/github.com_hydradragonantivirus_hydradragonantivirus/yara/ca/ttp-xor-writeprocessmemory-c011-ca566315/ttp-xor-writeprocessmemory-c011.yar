rule TTP_XOR_WriteProcessMemory_c011 {
  strings:
    $key_c011 = { 97 63 [2] a5 41 [2] a3 74 [2] 8d 74 [2] b2 68 }

  condition:
    any of them
}