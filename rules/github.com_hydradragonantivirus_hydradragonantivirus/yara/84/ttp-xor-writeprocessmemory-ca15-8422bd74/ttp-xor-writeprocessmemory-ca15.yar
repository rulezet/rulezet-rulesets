rule TTP_XOR_WriteProcessMemory_ca15 {
  strings:
    $key_ca15 = { 9d 67 [2] af 45 [2] a9 70 [2] 87 70 [2] b8 6c }

  condition:
    any of them
}