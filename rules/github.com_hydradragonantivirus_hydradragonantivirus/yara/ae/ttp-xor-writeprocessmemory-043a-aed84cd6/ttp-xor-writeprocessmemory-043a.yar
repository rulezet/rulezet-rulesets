rule TTP_XOR_WriteProcessMemory_043a {
  strings:
    $key_043a = { 53 48 [2] 61 6a [2] 67 5f [2] 49 5f [2] 76 43 }

  condition:
    any of them
}