rule TTP_XOR_WriteProcessMemory_023a {
  strings:
    $key_023a = { 55 48 [2] 67 6a [2] 61 5f [2] 4f 5f [2] 70 43 }

  condition:
    any of them
}