rule TTP_XOR_WriteProcessMemory_475f {
  strings:
    $key_475f = { 10 2d [2] 22 0f [2] 24 3a [2] 0a 3a [2] 35 26 }

  condition:
    any of them
}