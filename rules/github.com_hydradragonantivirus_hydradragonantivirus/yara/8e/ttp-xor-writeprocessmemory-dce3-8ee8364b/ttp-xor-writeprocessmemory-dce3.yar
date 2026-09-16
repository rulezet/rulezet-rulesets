rule TTP_XOR_WriteProcessMemory_dce3 {
  strings:
    $key_dce3 = { 8b 91 [2] b9 b3 [2] bf 86 [2] 91 86 [2] ae 9a }

  condition:
    any of them
}