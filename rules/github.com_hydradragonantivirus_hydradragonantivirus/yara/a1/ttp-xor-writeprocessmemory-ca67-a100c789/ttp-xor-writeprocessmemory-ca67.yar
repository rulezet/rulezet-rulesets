rule TTP_XOR_WriteProcessMemory_ca67 {
  strings:
    $key_ca67 = { 9d 15 [2] af 37 [2] a9 02 [2] 87 02 [2] b8 1e }

  condition:
    any of them
}