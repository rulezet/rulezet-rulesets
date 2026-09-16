rule TTP_XOR_WriteProcessMemory_c8fe {
  strings:
    $key_c8fe = { 9f 8c [2] ad ae [2] ab 9b [2] 85 9b [2] ba 87 }

  condition:
    any of them
}