rule TTP_XOR_WriteProcessMemory_ceb9 {
  strings:
    $key_ceb9 = { 99 cb [2] ab e9 [2] ad dc [2] 83 dc [2] bc c0 }

  condition:
    any of them
}