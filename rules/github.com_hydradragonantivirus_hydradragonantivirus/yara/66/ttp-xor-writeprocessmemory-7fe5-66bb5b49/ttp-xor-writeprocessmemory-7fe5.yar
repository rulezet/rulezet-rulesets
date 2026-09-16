rule TTP_XOR_WriteProcessMemory_7fe5 {
  strings:
    $key_7fe5 = { 28 97 [2] 1a b5 [2] 1c 80 [2] 32 80 [2] 0d 9c }

  condition:
    any of them
}