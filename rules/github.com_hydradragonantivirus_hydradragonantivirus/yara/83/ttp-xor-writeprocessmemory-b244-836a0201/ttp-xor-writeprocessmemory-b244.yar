rule TTP_XOR_WriteProcessMemory_b244 {
  strings:
    $key_b244 = { e5 36 [2] d7 14 [2] d1 21 [2] ff 21 [2] c0 3d }

  condition:
    any of them
}