rule TTP_XOR_WriteProcessMemory_246a {
  strings:
    $key_246a = { 73 18 [2] 41 3a [2] 47 0f [2] 69 0f [2] 56 13 }

  condition:
    any of them
}