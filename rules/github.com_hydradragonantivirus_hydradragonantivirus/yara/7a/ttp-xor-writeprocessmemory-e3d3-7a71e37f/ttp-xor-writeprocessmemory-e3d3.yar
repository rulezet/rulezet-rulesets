rule TTP_XOR_WriteProcessMemory_e3d3 {
  strings:
    $key_e3d3 = { b4 a1 [2] 86 83 [2] 80 b6 [2] ae b6 [2] 91 aa }

  condition:
    any of them
}