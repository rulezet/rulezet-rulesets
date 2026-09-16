rule TTP_XOR_WriteProcessMemory_f424 {
  strings:
    $key_f424 = { a3 56 [2] 91 74 [2] 97 41 [2] b9 41 [2] 86 5d }

  condition:
    any of them
}