rule TTP_XOR_WriteProcessMemory_502a {
  strings:
    $key_502a = { 07 58 [2] 35 7a [2] 33 4f [2] 1d 4f [2] 22 53 }

  condition:
    any of them
}