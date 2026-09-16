rule TTP_XOR_WriteProcessMemory_ca11 {
  strings:
    $key_ca11 = { 9d 63 [2] af 41 [2] a9 74 [2] 87 74 [2] b8 68 }

  condition:
    any of them
}