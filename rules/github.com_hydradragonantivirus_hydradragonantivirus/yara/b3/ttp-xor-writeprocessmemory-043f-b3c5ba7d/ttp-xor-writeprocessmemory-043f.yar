rule TTP_XOR_WriteProcessMemory_043f {
  strings:
    $key_043f = { 53 4d [2] 61 6f [2] 67 5a [2] 49 5a [2] 76 46 }

  condition:
    any of them
}