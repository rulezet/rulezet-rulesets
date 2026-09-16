rule TTP_XOR_WriteProcessMemory_f434 {
  strings:
    $key_f434 = { a3 46 [2] 91 64 [2] 97 51 [2] b9 51 [2] 86 4d }

  condition:
    any of them
}