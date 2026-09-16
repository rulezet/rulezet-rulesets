rule TTP_XOR_WriteProcessMemory_f50a {
  strings:
    $key_f50a = { a2 78 [2] 90 5a [2] 96 6f [2] b8 6f [2] 87 73 }

  condition:
    any of them
}