rule TTP_XOR_WriteProcessMemory_490a {
  strings:
    $key_490a = { 1e 78 [2] 2c 5a [2] 2a 6f [2] 04 6f [2] 3b 73 }

  condition:
    any of them
}