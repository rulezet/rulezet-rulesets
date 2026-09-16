rule TTP_XOR_WriteProcessMemory_f2d3 {
  strings:
    $key_f2d3 = { a5 a1 [2] 97 83 [2] 91 b6 [2] bf b6 [2] 80 aa }

  condition:
    any of them
}