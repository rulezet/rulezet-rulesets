rule TTP_XOR_WriteProcessMemory_790f {
  strings:
    $key_790f = { 2e 7d [2] 1c 5f [2] 1a 6a [2] 34 6a [2] 0b 76 }

  condition:
    any of them
}