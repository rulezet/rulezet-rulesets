rule TTP_XOR_WriteProcessMemory_501a {
  strings:
    $key_501a = { 07 68 [2] 35 4a [2] 33 7f [2] 1d 7f [2] 22 63 }

  condition:
    any of them
}