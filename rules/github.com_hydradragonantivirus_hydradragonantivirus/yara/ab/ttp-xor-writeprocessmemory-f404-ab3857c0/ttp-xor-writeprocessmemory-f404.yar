rule TTP_XOR_WriteProcessMemory_f404 {
  strings:
    $key_f404 = { a3 76 [2] 91 54 [2] 97 61 [2] b9 61 [2] 86 7d }

  condition:
    any of them
}