rule TTP_XOR_WriteProcessMemory_7805 {
  strings:
    $key_7805 = { 2f 77 [2] 1d 55 [2] 1b 60 [2] 35 60 [2] 0a 7c }

  condition:
    any of them
}