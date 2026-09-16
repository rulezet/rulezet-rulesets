rule TTP_XOR_WriteProcessMemory_a69a {
  strings:
    $key_a69a = { f1 e8 [2] c3 ca [2] c5 ff [2] eb ff [2] d4 e3 }

  condition:
    any of them
}