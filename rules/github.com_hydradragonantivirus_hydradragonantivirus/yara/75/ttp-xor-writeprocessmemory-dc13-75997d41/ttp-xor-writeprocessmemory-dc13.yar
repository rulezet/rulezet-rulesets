rule TTP_XOR_WriteProcessMemory_dc13 {
  strings:
    $key_dc13 = { 8b 61 [2] b9 43 [2] bf 76 [2] 91 76 [2] ae 6a }

  condition:
    any of them
}