rule TTP_XOR_WriteProcessMemory_ccd7 {
  strings:
    $key_ccd7 = { 9b a5 [2] a9 87 [2] af b2 [2] 81 b2 [2] be ae }

  condition:
    any of them
}