rule TTP_XOR_WriteProcessMemory_316a {
  strings:
    $key_316a = { 66 18 [2] 54 3a [2] 52 0f [2] 7c 0f [2] 43 13 }

  condition:
    any of them
}