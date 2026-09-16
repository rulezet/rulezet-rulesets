rule TTP_XOR_WriteProcessMemory_0d54 {
  strings:
    $key_0d54 = { 5a 26 [2] 68 04 [2] 6e 31 [2] 40 31 [2] 7f 2d }

  condition:
    any of them
}