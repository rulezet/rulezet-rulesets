rule TTP_XOR_WriteProcessMemory_286a {
  strings:
    $key_286a = { 7f 18 [2] 4d 3a [2] 4b 0f [2] 65 0f [2] 5a 13 }

  condition:
    any of them
}