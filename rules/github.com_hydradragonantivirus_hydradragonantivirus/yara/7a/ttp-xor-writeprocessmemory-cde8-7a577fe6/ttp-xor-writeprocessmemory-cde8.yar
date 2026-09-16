rule TTP_XOR_WriteProcessMemory_cde8 {
  strings:
    $key_cde8 = { 9a 9a [2] a8 b8 [2] ae 8d [2] 80 8d [2] bf 91 }

  condition:
    any of them
}