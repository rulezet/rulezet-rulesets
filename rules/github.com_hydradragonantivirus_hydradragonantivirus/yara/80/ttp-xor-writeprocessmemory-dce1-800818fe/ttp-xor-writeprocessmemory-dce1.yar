rule TTP_XOR_WriteProcessMemory_dce1 {
  strings:
    $key_dce1 = { 8b 93 [2] b9 b1 [2] bf 84 [2] 91 84 [2] ae 98 }

  condition:
    any of them
}