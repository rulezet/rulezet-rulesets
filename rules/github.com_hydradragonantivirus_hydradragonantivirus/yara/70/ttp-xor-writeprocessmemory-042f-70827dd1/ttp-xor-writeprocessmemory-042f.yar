rule TTP_XOR_WriteProcessMemory_042f {
  strings:
    $key_042f = { 53 5d [2] 61 7f [2] 67 4a [2] 49 4a [2] 76 56 }

  condition:
    any of them
}