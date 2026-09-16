rule TTP_XOR_WriteProcessMemory_f437 {
  strings:
    $key_f437 = { a3 45 [2] 91 67 [2] 97 52 [2] b9 52 [2] 86 4e }

  condition:
    any of them
}