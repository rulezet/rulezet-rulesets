rule TTP_XOR_WriteProcessMemory_cccb {
  strings:
    $key_cccb = { 9b b9 [2] a9 9b [2] af ae [2] 81 ae [2] be b2 }

  condition:
    any of them
}