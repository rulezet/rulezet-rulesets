rule TTP_XOR_WriteProcessMemory_31f4 {
  strings:
    $key_31f4 = { 66 86 [2] 54 a4 [2] 52 91 [2] 7c 91 [2] 43 8d }

  condition:
    any of them
}