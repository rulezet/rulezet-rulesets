rule TTP_XOR_WriteProcessMemory_500a {
  strings:
    $key_500a = { 07 78 [2] 35 5a [2] 33 6f [2] 1d 6f [2] 22 73 }

  condition:
    any of them
}