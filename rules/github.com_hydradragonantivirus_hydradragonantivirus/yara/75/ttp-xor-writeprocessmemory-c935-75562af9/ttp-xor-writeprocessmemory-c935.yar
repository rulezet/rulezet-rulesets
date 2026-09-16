rule TTP_XOR_WriteProcessMemory_c935 {
  strings:
    $key_c935 = { 9e 47 [2] ac 65 [2] aa 50 [2] 84 50 [2] bb 4c }

  condition:
    any of them
}