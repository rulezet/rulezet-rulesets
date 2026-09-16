rule TTP_XOR_WriteProcessMemory_2235 {
  strings:
    $key_2235 = { 75 47 [2] 47 65 [2] 41 50 [2] 6f 50 [2] 50 4c }

  condition:
    any of them
}