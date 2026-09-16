rule TTP_XOR_WriteProcessMemory_0144 {
  strings:
    $key_0144 = { 56 36 [2] 64 14 [2] 62 21 [2] 4c 21 [2] 73 3d }

  condition:
    any of them
}