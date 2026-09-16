rule TTP_XOR_WriteProcessMemory_0a20 {
  strings:
    $key_0a20 = { 5d 52 [2] 6f 70 [2] 69 45 [2] 47 45 [2] 78 59 }

  condition:
    any of them
}