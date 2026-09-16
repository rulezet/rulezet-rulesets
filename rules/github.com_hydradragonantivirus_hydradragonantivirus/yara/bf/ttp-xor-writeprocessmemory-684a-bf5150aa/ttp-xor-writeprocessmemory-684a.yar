rule TTP_XOR_WriteProcessMemory_684a {
  strings:
    $key_684a = { 3f 38 [2] 0d 1a [2] 0b 2f [2] 25 2f [2] 1a 33 }

  condition:
    any of them
}