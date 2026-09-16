rule TTP_XOR_WriteProcessMemory_040c {
  strings:
    $key_040c = { 53 7e [2] 61 5c [2] 67 69 [2] 49 69 [2] 76 75 }

  condition:
    any of them
}