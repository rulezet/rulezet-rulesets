rule TTP_XOR_WriteProcessMemory_94e5 {
  strings:
    $key_94e5 = { c3 97 [2] f1 b5 [2] f7 80 [2] d9 80 [2] e6 9c }

  condition:
    any of them
}