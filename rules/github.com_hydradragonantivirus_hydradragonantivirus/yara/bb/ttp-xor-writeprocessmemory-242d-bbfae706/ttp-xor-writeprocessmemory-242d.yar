rule TTP_XOR_WriteProcessMemory_242d {
  strings:
    $key_242d = { 73 5f [2] 41 7d [2] 47 48 [2] 69 48 [2] 56 54 }

  condition:
    any of them
}