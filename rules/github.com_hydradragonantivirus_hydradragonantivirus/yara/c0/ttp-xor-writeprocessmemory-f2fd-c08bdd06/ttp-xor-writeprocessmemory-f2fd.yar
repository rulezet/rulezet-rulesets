rule TTP_XOR_WriteProcessMemory_f2fd {
  strings:
    $key_f2fd = { a5 8f [2] 97 ad [2] 91 98 [2] bf 98 [2] 80 84 }

  condition:
    any of them
}