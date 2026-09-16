rule TTP_XOR_WriteProcessMemory_f8df {
  strings:
    $key_f8df = { af ad [2] 9d 8f [2] 9b ba [2] b5 ba [2] 8a a6 }

  condition:
    any of them
}