rule TTP_XOR_WriteProcessMemory_045d {
  strings:
    $key_045d = { 53 2f [2] 61 0d [2] 67 38 [2] 49 38 [2] 76 24 }

  condition:
    any of them
}