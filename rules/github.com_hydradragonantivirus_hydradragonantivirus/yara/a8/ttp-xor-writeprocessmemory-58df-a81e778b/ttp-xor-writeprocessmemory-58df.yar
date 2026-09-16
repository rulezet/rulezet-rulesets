rule TTP_XOR_WriteProcessMemory_58df {
  strings:
    $key_58df = { 0f ad [2] 3d 8f [2] 3b ba [2] 15 ba [2] 2a a6 }

  condition:
    any of them
}