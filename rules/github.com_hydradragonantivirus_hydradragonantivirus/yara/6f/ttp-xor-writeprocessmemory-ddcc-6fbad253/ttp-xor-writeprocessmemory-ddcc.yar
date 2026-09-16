rule TTP_XOR_WriteProcessMemory_ddcc {
  strings:
    $key_ddcc = { 8a be [2] b8 9c [2] be a9 [2] 90 a9 [2] af b5 }

  condition:
    any of them
}