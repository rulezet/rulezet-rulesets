rule TTP_XOR_WriteProcessMemory_0654 {
  strings:
    $key_0654 = { 51 26 [2] 63 04 [2] 65 31 [2] 4b 31 [2] 74 2d }

  condition:
    any of them
}