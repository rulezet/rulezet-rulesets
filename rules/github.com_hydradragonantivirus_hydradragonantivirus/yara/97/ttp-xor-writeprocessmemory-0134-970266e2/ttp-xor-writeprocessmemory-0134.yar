rule TTP_XOR_WriteProcessMemory_0134 {
  strings:
    $key_0134 = { 56 46 [2] 64 64 [2] 62 51 [2] 4c 51 [2] 73 4d }

  condition:
    any of them
}