rule TTP_XOR_WriteProcessMemory_b04c {
  strings:
    $key_b04c = { e7 3e [2] d5 1c [2] d3 29 [2] fd 29 [2] c2 35 }

  condition:
    any of them
}