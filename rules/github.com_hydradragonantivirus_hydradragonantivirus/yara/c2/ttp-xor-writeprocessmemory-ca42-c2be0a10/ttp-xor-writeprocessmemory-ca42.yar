rule TTP_XOR_WriteProcessMemory_ca42 {
  strings:
    $key_ca42 = { 9d 30 [2] af 12 [2] a9 27 [2] 87 27 [2] b8 3b }

  condition:
    any of them
}