rule TTP_XOR_WriteProcessMemory_b0af {
  strings:
    $key_b0af = { e7 dd [2] d5 ff [2] d3 ca [2] fd ca [2] c2 d6 }

  condition:
    any of them
}