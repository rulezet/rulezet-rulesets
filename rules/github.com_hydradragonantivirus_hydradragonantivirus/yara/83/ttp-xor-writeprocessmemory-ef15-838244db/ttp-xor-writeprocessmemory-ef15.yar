rule TTP_XOR_WriteProcessMemory_ef15 {
  strings:
    $key_ef15 = { b8 67 [2] 8a 45 [2] 8c 70 [2] a2 70 [2] 9d 6c }

  condition:
    any of them
}