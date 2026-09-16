rule TTP_XOR_WriteProcessMemory_151d {
  strings:
    $key_151d = { 42 6f [2] 70 4d [2] 76 78 [2] 58 78 [2] 67 64 }

  condition:
    any of them
}