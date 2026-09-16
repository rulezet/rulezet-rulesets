rule TTP_XOR_WriteProcessMemory_00d7 {
  strings:
    $key_00d7 = { 57 a5 [2] 65 87 [2] 63 b2 [2] 4d b2 [2] 72 ae }

  condition:
    any of them
}