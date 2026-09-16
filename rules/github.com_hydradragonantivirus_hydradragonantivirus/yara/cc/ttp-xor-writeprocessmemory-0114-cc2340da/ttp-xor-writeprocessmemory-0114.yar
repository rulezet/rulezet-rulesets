rule TTP_XOR_WriteProcessMemory_0114 {
  strings:
    $key_0114 = { 56 66 [2] 64 44 [2] 62 71 [2] 4c 71 [2] 73 6d }

  condition:
    any of them
}