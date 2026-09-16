rule TTP_XOR_WriteProcessMemory_dccc {
  strings:
    $key_dccc = { 8b be [2] b9 9c [2] bf a9 [2] 91 a9 [2] ae b5 }

  condition:
    any of them
}