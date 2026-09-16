rule TTP_XOR_WriteProcessMemory_f50d {
  strings:
    $key_f50d = { a2 7f [2] 90 5d [2] 96 68 [2] b8 68 [2] 87 74 }

  condition:
    any of them
}