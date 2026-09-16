rule TTP_XOR_WriteProcessMemory_f835 {
  strings:
    $key_f835 = { af 47 [2] 9d 65 [2] 9b 50 [2] b5 50 [2] 8a 4c }

  condition:
    any of them
}