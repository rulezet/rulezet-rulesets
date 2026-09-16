rule TTP_XOR_WriteProcessMemory_c1df {
  strings:
    $key_c1df = { 96 ad [2] a4 8f [2] a2 ba [2] 8c ba [2] b3 a6 }

  condition:
    any of them
}