rule TTP_XOR_WriteProcessMemory_5ace {
  strings:
    $key_5ace = { 0d bc [2] 3f 9e [2] 39 ab [2] 17 ab [2] 28 b7 }

  condition:
    any of them
}