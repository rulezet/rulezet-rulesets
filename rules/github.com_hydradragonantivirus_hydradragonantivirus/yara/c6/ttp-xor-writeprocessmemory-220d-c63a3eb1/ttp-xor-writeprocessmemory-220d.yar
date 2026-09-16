rule TTP_XOR_WriteProcessMemory_220d {
  strings:
    $key_220d = { 75 7f [2] 47 5d [2] 41 68 [2] 6f 68 [2] 50 74 }

  condition:
    any of them
}