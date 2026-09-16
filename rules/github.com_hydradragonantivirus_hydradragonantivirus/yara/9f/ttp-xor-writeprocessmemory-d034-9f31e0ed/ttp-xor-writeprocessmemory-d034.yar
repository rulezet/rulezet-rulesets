rule TTP_XOR_WriteProcessMemory_d034 {
  strings:
    $key_d034 = { 87 46 [2] b5 64 [2] b3 51 [2] 9d 51 [2] a2 4d }

  condition:
    any of them
}