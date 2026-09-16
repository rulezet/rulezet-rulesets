rule TTP_XOR_WriteProcessMemory_e875 {
  strings:
    $key_e875 = { bf 07 [2] 8d 25 [2] 8b 10 [2] a5 10 [2] 9a 0c }

  condition:
    any of them
}