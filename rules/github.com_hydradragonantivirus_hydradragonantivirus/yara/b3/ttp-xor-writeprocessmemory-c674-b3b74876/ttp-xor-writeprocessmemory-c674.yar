rule TTP_XOR_WriteProcessMemory_c674 {
  strings:
    $key_c674 = { 91 06 [2] a3 24 [2] a5 11 [2] 8b 11 [2] b4 0d }

  condition:
    any of them
}