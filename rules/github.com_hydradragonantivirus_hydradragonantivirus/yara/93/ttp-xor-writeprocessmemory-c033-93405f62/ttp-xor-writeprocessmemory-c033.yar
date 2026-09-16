rule TTP_XOR_WriteProcessMemory_c033 {
  strings:
    $key_c033 = { 97 41 [2] a5 63 [2] a3 56 [2] 8d 56 [2] b2 4a }

  condition:
    any of them
}