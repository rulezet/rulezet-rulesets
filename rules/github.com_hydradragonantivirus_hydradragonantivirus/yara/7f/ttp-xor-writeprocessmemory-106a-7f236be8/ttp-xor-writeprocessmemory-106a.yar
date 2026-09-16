rule TTP_XOR_WriteProcessMemory_106a {
  strings:
    $key_106a = { 47 18 [2] 75 3a [2] 73 0f [2] 5d 0f [2] 62 13 }

  condition:
    any of them
}