rule TTP_XOR_WriteProcessMemory_dce9 {
  strings:
    $key_dce9 = { 8b 9b [2] b9 b9 [2] bf 8c [2] 91 8c [2] ae 90 }

  condition:
    any of them
}