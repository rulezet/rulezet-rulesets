rule TTP_XOR_WriteProcessMemory_94f4 {
  strings:
    $key_94f4 = { c3 86 [2] f1 a4 [2] f7 91 [2] d9 91 [2] e6 8d }

  condition:
    any of them
}