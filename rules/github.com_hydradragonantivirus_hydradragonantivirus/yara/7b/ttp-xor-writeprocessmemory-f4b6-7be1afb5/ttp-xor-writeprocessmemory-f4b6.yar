rule TTP_XOR_WriteProcessMemory_f4b6 {
  strings:
    $key_f4b6 = { a3 c4 [2] 91 e6 [2] 97 d3 [2] b9 d3 [2] 86 cf }

  condition:
    any of them
}