rule TTP_XOR_WriteProcessMemory_c653 {
  strings:
    $key_c653 = { 91 21 [2] a3 03 [2] a5 36 [2] 8b 36 [2] b4 2a }

  condition:
    any of them
}