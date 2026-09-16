rule TTP_XOR_WriteProcessMemory_c01b {
  strings:
    $key_c01b = { 97 69 [2] a5 4b [2] a3 7e [2] 8d 7e [2] b2 62 }

  condition:
    any of them
}