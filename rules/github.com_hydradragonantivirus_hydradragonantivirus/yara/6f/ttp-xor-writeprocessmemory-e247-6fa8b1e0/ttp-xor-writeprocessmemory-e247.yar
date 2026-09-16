rule TTP_XOR_WriteProcessMemory_e247 {
  strings:
    $key_e247 = { b5 35 [2] 87 17 [2] 81 22 [2] af 22 [2] 90 3e }

  condition:
    any of them
}