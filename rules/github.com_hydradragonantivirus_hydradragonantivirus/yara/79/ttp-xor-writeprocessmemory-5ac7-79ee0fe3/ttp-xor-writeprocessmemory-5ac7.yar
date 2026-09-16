rule TTP_XOR_WriteProcessMemory_5ac7 {
  strings:
    $key_5ac7 = { 0d b5 [2] 3f 97 [2] 39 a2 [2] 17 a2 [2] 28 be }

  condition:
    any of them
}