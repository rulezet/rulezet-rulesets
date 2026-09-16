rule TTP_XOR_WriteProcessMemory_3875 {
  strings:
    $key_3875 = { 6f 07 [2] 5d 25 [2] 5b 10 [2] 75 10 [2] 4a 0c }

  condition:
    any of them
}