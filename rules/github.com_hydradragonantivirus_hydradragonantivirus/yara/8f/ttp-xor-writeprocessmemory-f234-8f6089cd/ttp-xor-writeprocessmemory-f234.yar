rule TTP_XOR_WriteProcessMemory_f234 {
  strings:
    $key_f234 = { a5 46 [2] 97 64 [2] 91 51 [2] bf 51 [2] 80 4d }

  condition:
    any of them
}