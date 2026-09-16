rule TTP_XOR_WriteProcessMemory_caec {
  strings:
    $key_caec = { 9d 9e [2] af bc [2] a9 89 [2] 87 89 [2] b8 95 }

  condition:
    any of them
}