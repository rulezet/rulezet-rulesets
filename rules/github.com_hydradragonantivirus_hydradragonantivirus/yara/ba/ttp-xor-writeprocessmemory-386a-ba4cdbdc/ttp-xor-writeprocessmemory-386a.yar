rule TTP_XOR_WriteProcessMemory_386a {
  strings:
    $key_386a = { 6f 18 [2] 5d 3a [2] 5b 0f [2] 75 0f [2] 4a 13 }

  condition:
    any of them
}