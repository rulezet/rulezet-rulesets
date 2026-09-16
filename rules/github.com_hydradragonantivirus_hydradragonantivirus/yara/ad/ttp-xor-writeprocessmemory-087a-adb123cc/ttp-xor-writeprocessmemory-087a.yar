rule TTP_XOR_WriteProcessMemory_087a {
  strings:
    $key_087a = { 5f 08 [2] 6d 2a [2] 6b 1f [2] 45 1f [2] 7a 03 }

  condition:
    any of them
}