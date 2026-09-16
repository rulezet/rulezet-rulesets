rule TTP_XOR_WriteProcessMemory_cac3 {
  strings:
    $key_cac3 = { 9d b1 [2] af 93 [2] a9 a6 [2] 87 a6 [2] b8 ba }

  condition:
    any of them
}