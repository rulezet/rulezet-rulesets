rule TTP_XOR_WriteProcessMemory_dce8 {
  strings:
    $key_dce8 = { 8b 9a [2] b9 b8 [2] bf 8d [2] 91 8d [2] ae 91 }

  condition:
    any of them
}