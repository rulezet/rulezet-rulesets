rule TTP_XOR_WriteProcessMemory_78c6 {
  strings:
    $key_78c6 = { 2f b4 [2] 1d 96 [2] 1b a3 [2] 35 a3 [2] 0a bf }

  condition:
    any of them
}