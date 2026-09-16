rule TTP_XOR_WriteProcessMemory_242c {
  strings:
    $key_242c = { 73 5e [2] 41 7c [2] 47 49 [2] 69 49 [2] 56 55 }

  condition:
    any of them
}