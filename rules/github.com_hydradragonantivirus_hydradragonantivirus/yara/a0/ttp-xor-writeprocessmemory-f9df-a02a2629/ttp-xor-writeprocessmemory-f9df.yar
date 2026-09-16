rule TTP_XOR_WriteProcessMemory_f9df {
  strings:
    $key_f9df = { ae ad [2] 9c 8f [2] 9a ba [2] b4 ba [2] 8b a6 }

  condition:
    any of them
}