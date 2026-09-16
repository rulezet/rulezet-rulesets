rule TTP_XOR_WriteProcessMemory_fbe5 {
  strings:
    $key_fbe5 = { ac 97 [2] 9e b5 [2] 98 80 [2] b6 80 [2] 89 9c }

  condition:
    any of them
}