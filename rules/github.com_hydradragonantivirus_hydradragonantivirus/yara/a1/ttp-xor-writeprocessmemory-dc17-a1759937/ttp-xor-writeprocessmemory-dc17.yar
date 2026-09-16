rule TTP_XOR_WriteProcessMemory_dc17 {
  strings:
    $key_dc17 = { 8b 65 [2] b9 47 [2] bf 72 [2] 91 72 [2] ae 6e }

  condition:
    any of them
}