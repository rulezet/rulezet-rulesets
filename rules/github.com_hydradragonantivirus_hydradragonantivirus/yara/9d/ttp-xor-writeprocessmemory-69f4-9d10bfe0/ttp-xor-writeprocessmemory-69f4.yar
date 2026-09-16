rule TTP_XOR_WriteProcessMemory_69f4 {
  strings:
    $key_69f4 = { 3e 86 [2] 0c a4 [2] 0a 91 [2] 24 91 [2] 1b 8d }

  condition:
    any of them
}