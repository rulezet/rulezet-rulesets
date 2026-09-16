rule TTP_XOR_WriteProcessMemory_dc37 {
  strings:
    $key_dc37 = { 8b 45 [2] b9 67 [2] bf 52 [2] 91 52 [2] ae 4e }

  condition:
    any of them
}