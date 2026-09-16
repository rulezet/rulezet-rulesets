rule TTP_XOR_WriteProcessMemory_351a {
  strings:
    $key_351a = { 62 68 [2] 50 4a [2] 56 7f [2] 78 7f [2] 47 63 }

  condition:
    any of them
}