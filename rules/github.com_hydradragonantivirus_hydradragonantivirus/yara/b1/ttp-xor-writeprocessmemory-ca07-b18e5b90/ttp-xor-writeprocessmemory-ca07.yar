rule TTP_XOR_WriteProcessMemory_ca07 {
  strings:
    $key_ca07 = { 9d 75 [2] af 57 [2] a9 62 [2] 87 62 [2] b8 7e }

  condition:
    any of them
}