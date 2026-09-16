rule TTP_XOR_WriteProcessMemory_daef {
  strings:
    $key_daef = { 8d 9d [2] bf bf [2] b9 8a [2] 97 8a [2] a8 96 }

  condition:
    any of them
}