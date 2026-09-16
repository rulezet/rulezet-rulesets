rule TTP_XOR_WriteProcessMemory_696a {
  strings:
    $key_696a = { 3e 18 [2] 0c 3a [2] 0a 0f [2] 24 0f [2] 1b 13 }

  condition:
    any of them
}