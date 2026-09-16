rule TTP_XOR_WriteProcessMemory_b03c {
  strings:
    $key_b03c = { e7 4e [2] d5 6c [2] d3 59 [2] fd 59 [2] c2 45 }

  condition:
    any of them
}