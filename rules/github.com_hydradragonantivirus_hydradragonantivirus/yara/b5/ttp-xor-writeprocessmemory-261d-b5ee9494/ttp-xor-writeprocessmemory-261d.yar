rule TTP_XOR_WriteProcessMemory_261d {
  strings:
    $key_261d = { 71 6f [2] 43 4d [2] 45 78 [2] 6b 78 [2] 54 64 }

  condition:
    any of them
}