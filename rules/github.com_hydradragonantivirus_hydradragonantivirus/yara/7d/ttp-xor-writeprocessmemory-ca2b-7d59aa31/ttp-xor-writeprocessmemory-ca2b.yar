rule TTP_XOR_WriteProcessMemory_ca2b {
  strings:
    $key_ca2b = { 9d 59 [2] af 7b [2] a9 4e [2] 87 4e [2] b8 52 }

  condition:
    any of them
}