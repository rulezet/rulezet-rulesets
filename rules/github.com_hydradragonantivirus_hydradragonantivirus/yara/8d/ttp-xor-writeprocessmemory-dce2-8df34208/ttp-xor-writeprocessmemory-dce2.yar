rule TTP_XOR_WriteProcessMemory_dce2 {
  strings:
    $key_dce2 = { 8b 90 [2] b9 b2 [2] bf 87 [2] 91 87 [2] ae 9b }

  condition:
    any of them
}