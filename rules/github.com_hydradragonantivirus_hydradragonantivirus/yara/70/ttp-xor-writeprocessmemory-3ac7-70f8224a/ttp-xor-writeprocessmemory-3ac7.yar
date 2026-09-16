rule TTP_XOR_WriteProcessMemory_3ac7 {
  strings:
    $key_3ac7 = { 6d b5 [2] 5f 97 [2] 59 a2 [2] 77 a2 [2] 48 be }

  condition:
    any of them
}