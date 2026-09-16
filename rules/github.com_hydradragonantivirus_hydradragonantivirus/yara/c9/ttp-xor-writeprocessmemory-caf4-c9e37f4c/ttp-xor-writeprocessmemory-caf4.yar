rule TTP_XOR_WriteProcessMemory_caf4 {
  strings:
    $key_caf4 = { 9d 86 [2] af a4 [2] a9 91 [2] 87 91 [2] b8 8d }

  condition:
    any of them
}