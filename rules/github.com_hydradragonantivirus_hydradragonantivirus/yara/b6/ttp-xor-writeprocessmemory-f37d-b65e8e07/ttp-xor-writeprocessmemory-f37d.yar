rule TTP_XOR_WriteProcessMemory_f37d {
  strings:
    $key_f37d = { a4 0f [2] 96 2d [2] 90 18 [2] be 18 [2] 81 04 }

  condition:
    any of them
}