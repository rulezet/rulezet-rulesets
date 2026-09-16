rule TTP_XOR_WriteProcessMemory_0954 {
  strings:
    $key_0954 = { 5e 26 [2] 6c 04 [2] 6a 31 [2] 44 31 [2] 7b 2d }

  condition:
    any of them
}