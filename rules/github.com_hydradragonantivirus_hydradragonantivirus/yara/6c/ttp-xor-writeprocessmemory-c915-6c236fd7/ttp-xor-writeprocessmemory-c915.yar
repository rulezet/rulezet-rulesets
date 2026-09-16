rule TTP_XOR_WriteProcessMemory_c915 {
  strings:
    $key_c915 = { 9e 67 [2] ac 45 [2] aa 70 [2] 84 70 [2] bb 6c }

  condition:
    any of them
}