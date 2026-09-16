rule TTP_XOR_WriteProcessMemory_ca70 {
  strings:
    $key_ca70 = { 9d 02 [2] af 20 [2] a9 15 [2] 87 15 [2] b8 09 }

  condition:
    any of them
}