rule TTP_XOR_WriteProcessMemory_5601 {
  strings:
    $key_5601 = { 01 73 [2] 33 51 [2] 35 64 [2] 1b 64 [2] 24 78 }

  condition:
    any of them
}