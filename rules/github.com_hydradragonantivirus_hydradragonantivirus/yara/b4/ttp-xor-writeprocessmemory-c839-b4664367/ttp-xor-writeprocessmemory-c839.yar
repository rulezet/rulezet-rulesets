rule TTP_XOR_WriteProcessMemory_c839 {
  strings:
    $key_c839 = { 9f 4b [2] ad 69 [2] ab 5c [2] 85 5c [2] ba 40 }

  condition:
    any of them
}