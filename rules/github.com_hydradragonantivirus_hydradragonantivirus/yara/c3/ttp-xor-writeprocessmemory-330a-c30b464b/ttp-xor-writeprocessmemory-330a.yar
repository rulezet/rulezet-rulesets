rule TTP_XOR_WriteProcessMemory_330a {
  strings:
    $key_330a = { 64 78 [2] 56 5a [2] 50 6f [2] 7e 6f [2] 41 73 }

  condition:
    any of them
}