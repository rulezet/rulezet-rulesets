rule TTP_XOR_WriteProcessMemory_0cdd {
  strings:
    $key_0cdd = { 5b af [2] 69 8d [2] 6f b8 [2] 41 b8 [2] 7e a4 }

  condition:
    any of them
}