rule TTP_XOR_WriteProcessMemory_e805 {
  strings:
    $key_e805 = { bf 77 [2] 8d 55 [2] 8b 60 [2] a5 60 [2] 9a 7c }

  condition:
    any of them
}