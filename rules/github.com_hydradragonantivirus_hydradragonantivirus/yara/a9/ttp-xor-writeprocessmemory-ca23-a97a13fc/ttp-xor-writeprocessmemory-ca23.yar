rule TTP_XOR_WriteProcessMemory_ca23 {
  strings:
    $key_ca23 = { 9d 51 [2] af 73 [2] a9 46 [2] 87 46 [2] b8 5a }

  condition:
    any of them
}