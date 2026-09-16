rule TTP_XOR_WriteProcessMemory_0515 {
  strings:
    $key_0515 = { 52 67 [2] 60 45 [2] 66 70 [2] 48 70 [2] 77 6c }

  condition:
    any of them
}