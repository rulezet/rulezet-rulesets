rule TTP_XOR_WriteProcessMemory_dc53 {
  strings:
    $key_dc53 = { 8b 21 [2] b9 03 [2] bf 36 [2] 91 36 [2] ae 2a }

  condition:
    any of them
}