rule TTP_XOR_WriteProcessMemory_c847 {
  strings:
    $key_c847 = { 9f 35 [2] ad 17 [2] ab 22 [2] 85 22 [2] ba 3e }

  condition:
    any of them
}