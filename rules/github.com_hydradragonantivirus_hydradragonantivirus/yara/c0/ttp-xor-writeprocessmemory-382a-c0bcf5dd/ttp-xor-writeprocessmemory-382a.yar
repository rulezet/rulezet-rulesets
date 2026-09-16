rule TTP_XOR_WriteProcessMemory_382a {
  strings:
    $key_382a = { 6f 58 [2] 5d 7a [2] 5b 4f [2] 75 4f [2] 4a 53 }

  condition:
    any of them
}