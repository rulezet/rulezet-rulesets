rule TTP_XOR_WriteProcessMemory_2921 {
  strings:
    $key_2921 = { 7e 53 [2] 4c 71 [2] 4a 44 [2] 64 44 [2] 5b 58 }

  condition:
    any of them
}