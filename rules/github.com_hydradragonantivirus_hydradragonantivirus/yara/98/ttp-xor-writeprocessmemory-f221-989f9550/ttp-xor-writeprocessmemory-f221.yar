rule TTP_XOR_WriteProcessMemory_f221 {
  strings:
    $key_f221 = { a5 53 [2] 97 71 [2] 91 44 [2] bf 44 [2] 80 58 }

  condition:
    any of them
}