rule TTP_XOR_WriteProcessMemory_ceb3 {
  strings:
    $key_ceb3 = { 99 c1 [2] ab e3 [2] ad d6 [2] 83 d6 [2] bc ca }

  condition:
    any of them
}