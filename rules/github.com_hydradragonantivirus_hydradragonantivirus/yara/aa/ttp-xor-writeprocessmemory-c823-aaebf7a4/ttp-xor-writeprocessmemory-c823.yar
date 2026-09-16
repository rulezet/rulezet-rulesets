rule TTP_XOR_WriteProcessMemory_c823 {
  strings:
    $key_c823 = { 9f 51 [2] ad 73 [2] ab 46 [2] 85 46 [2] ba 5a }

  condition:
    any of them
}