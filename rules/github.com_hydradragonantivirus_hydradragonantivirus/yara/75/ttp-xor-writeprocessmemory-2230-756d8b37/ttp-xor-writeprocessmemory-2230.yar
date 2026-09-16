rule TTP_XOR_WriteProcessMemory_2230 {
  strings:
    $key_2230 = { 75 42 [2] 47 60 [2] 41 55 [2] 6f 55 [2] 50 49 }

  condition:
    any of them
}