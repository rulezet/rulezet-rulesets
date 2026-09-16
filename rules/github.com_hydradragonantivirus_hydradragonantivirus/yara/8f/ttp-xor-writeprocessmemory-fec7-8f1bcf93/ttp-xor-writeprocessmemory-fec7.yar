rule TTP_XOR_WriteProcessMemory_fec7 {
  strings:
    $key_fec7 = { a9 b5 [2] 9b 97 [2] 9d a2 [2] b3 a2 [2] 8c be }

  condition:
    any of them
}