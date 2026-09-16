rule TTP_XOR_WriteProcessMemory_cc44 {
  strings:
    $key_cc44 = { 9b 36 [2] a9 14 [2] af 21 [2] 81 21 [2] be 3d }

  condition:
    any of them
}