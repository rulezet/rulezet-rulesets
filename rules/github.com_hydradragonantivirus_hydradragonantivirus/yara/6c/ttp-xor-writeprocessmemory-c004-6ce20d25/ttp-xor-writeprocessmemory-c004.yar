rule TTP_XOR_WriteProcessMemory_c004 {
  strings:
    $key_c004 = { 97 76 [2] a5 54 [2] a3 61 [2] 8d 61 [2] b2 7d }

  condition:
    any of them
}