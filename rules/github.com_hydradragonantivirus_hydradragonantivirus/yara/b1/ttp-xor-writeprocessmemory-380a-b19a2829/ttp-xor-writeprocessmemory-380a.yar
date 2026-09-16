rule TTP_XOR_WriteProcessMemory_380a {
  strings:
    $key_380a = { 6f 78 [2] 5d 5a [2] 5b 6f [2] 75 6f [2] 4a 73 }

  condition:
    any of them
}