rule TTP_XOR_WriteProcessMemory_a2af {
  strings:
    $key_a2af = { f5 dd [2] c7 ff [2] c1 ca [2] ef ca [2] d0 d6 }

  condition:
    any of them
}