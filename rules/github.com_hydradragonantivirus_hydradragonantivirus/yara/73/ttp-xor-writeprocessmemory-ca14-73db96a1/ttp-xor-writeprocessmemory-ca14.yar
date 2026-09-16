rule TTP_XOR_WriteProcessMemory_ca14 {
  strings:
    $key_ca14 = { 9d 66 [2] af 44 [2] a9 71 [2] 87 71 [2] b8 6d }

  condition:
    any of them
}