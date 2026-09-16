rule TTP_XOR_WriteProcessMemory_041d {
  strings:
    $key_041d = { 53 6f [2] 61 4d [2] 67 78 [2] 49 78 [2] 76 64 }

  condition:
    any of them
}