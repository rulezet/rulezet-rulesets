rule TTP_XOR_WriteProcessMemory_012d {
  strings:
    $key_012d = { 56 5f [2] 64 7d [2] 62 48 [2] 4c 48 [2] 73 54 }

  condition:
    any of them
}