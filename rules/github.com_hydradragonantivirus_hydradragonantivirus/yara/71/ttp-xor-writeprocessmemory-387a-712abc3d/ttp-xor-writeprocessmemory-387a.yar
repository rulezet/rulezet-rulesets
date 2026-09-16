rule TTP_XOR_WriteProcessMemory_387a {
  strings:
    $key_387a = { 6f 08 [2] 5d 2a [2] 5b 1f [2] 75 1f [2] 4a 03 }

  condition:
    any of them
}