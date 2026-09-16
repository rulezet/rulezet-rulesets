rule TTP_XOR_WriteProcessMemory_dc11 {
  strings:
    $key_dc11 = { 8b 63 [2] b9 41 [2] bf 74 [2] 91 74 [2] ae 68 }

  condition:
    any of them
}