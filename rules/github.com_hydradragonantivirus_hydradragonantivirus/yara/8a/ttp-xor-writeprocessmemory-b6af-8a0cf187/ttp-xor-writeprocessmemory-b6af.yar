rule TTP_XOR_WriteProcessMemory_b6af {
  strings:
    $key_b6af = { e1 dd [2] d3 ff [2] d5 ca [2] fb ca [2] c4 d6 }

  condition:
    any of them
}