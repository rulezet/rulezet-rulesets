rule TTP_XOR_WriteProcessMemory_ca92 {
  strings:
    $key_ca92 = { 9d e0 [2] af c2 [2] a9 f7 [2] 87 f7 [2] b8 eb }

  condition:
    any of them
}