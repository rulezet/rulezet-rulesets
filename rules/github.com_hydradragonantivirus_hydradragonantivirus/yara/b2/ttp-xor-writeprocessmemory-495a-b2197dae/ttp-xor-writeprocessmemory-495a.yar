rule TTP_XOR_WriteProcessMemory_495a {
  strings:
    $key_495a = { 1e 28 [2] 2c 0a [2] 2a 3f [2] 04 3f [2] 3b 23 }

  condition:
    any of them
}