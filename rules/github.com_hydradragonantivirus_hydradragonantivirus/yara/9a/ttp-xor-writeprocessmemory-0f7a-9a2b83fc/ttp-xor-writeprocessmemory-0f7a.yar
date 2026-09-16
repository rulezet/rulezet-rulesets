rule TTP_XOR_WriteProcessMemory_0f7a {
  strings:
    $key_0f7a = { 58 08 [2] 6a 2a [2] 6c 1f [2] 42 1f [2] 7d 03 }

  condition:
    any of them
}