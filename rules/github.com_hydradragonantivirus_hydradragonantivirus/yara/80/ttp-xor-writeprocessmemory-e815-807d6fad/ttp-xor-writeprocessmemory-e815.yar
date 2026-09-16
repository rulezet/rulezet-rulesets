rule TTP_XOR_WriteProcessMemory_e815 {
  strings:
    $key_e815 = { bf 67 [2] 8d 45 [2] 8b 70 [2] a5 70 [2] 9a 6c }

  condition:
    any of them
}