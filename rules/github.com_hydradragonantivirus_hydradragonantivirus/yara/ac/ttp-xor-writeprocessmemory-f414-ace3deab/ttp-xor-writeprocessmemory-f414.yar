rule TTP_XOR_WriteProcessMemory_f414 {
  strings:
    $key_f414 = { a3 66 [2] 91 44 [2] 97 71 [2] b9 71 [2] 86 6d }

  condition:
    any of them
}