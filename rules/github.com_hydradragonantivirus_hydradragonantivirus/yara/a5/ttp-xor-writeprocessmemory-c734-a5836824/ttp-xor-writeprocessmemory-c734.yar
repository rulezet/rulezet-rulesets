rule TTP_XOR_WriteProcessMemory_c734 {
  strings:
    $key_c734 = { 90 46 [2] a2 64 [2] a4 51 [2] 8a 51 [2] b5 4d }

  condition:
    any of them
}