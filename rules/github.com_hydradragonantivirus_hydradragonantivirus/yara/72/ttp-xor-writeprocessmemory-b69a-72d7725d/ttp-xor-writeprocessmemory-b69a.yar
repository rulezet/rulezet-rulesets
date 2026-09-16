rule TTP_XOR_WriteProcessMemory_b69a {
  strings:
    $key_b69a = { e1 e8 [2] d3 ca [2] d5 ff [2] fb ff [2] c4 e3 }

  condition:
    any of them
}