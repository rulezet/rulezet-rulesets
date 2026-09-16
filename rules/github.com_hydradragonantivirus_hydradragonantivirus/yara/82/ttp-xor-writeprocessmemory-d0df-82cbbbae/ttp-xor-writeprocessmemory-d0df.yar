rule TTP_XOR_WriteProcessMemory_d0df {
  strings:
    $key_d0df = { 87 ad [2] b5 8f [2] b3 ba [2] 9d ba [2] a2 a6 }

  condition:
    any of them
}