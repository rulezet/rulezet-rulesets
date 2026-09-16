rule TTP_XOR_WriteProcessMemory_f325 {
  strings:
    $key_f325 = { a4 57 [2] 96 75 [2] 90 40 [2] be 40 [2] 81 5c }

  condition:
    any of them
}