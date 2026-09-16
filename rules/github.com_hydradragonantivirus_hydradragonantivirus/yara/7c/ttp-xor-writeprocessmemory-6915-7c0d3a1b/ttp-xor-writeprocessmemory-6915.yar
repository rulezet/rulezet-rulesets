rule TTP_XOR_WriteProcessMemory_6915 {
  strings:
    $key_6915 = { 3e 67 [2] 0c 45 [2] 0a 70 [2] 24 70 [2] 1b 6c }

  condition:
    any of them
}