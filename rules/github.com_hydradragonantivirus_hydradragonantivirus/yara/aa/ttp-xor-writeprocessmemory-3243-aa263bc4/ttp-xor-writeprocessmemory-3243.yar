rule TTP_XOR_WriteProcessMemory_3243 {
  strings:
    $key_3243 = { 65 31 [2] 57 13 [2] 51 26 [2] 7f 26 [2] 40 3a }

  condition:
    any of them
}