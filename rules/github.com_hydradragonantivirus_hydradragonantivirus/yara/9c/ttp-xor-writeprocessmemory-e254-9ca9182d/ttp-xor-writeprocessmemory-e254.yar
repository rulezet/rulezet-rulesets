rule TTP_XOR_WriteProcessMemory_e254 {
  strings:
    $key_e254 = { b5 26 [2] 87 04 [2] 81 31 [2] af 31 [2] 90 2d }

  condition:
    any of them
}