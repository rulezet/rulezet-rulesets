rule TTP_XOR_WriteProcessMemory_fbe3 {
  strings:
    $key_fbe3 = { ac 91 [2] 9e b3 [2] 98 86 [2] b6 86 [2] 89 9a }

  condition:
    any of them
}