rule TTP_XOR_WriteProcessMemory_281a {
  strings:
    $key_281a = { 7f 68 [2] 4d 4a [2] 4b 7f [2] 65 7f [2] 5a 63 }

  condition:
    any of them
}