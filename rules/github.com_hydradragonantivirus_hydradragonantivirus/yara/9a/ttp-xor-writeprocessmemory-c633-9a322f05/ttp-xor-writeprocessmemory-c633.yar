rule TTP_XOR_WriteProcessMemory_c633 {
  strings:
    $key_c633 = { 91 41 [2] a3 63 [2] a5 56 [2] 8b 56 [2] b4 4a }

  condition:
    any of them
}