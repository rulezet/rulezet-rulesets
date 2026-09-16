rule TTP_XOR_WriteProcessMemory_0ace {
  strings:
    $key_0ace = { 5d bc [2] 6f 9e [2] 69 ab [2] 47 ab [2] 78 b7 }

  condition:
    any of them
}