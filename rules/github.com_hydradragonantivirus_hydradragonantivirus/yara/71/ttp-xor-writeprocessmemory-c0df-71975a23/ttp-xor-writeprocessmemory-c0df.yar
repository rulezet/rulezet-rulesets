rule TTP_XOR_WriteProcessMemory_c0df {
  strings:
    $key_c0df = { 97 ad [2] a5 8f [2] a3 ba [2] 8d ba [2] b2 a6 }

  condition:
    any of them
}