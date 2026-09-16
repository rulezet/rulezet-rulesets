rule TTP_XOR_WriteProcessMemory_ca54 {
  strings:
    $key_ca54 = { 9d 26 [2] af 04 [2] a9 31 [2] 87 31 [2] b8 2d }

  condition:
    any of them
}