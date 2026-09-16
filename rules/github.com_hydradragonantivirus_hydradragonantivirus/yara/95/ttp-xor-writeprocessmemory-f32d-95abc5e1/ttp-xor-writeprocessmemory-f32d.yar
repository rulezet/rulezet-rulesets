rule TTP_XOR_WriteProcessMemory_f32d {
  strings:
    $key_f32d = { a4 5f [2] 96 7d [2] 90 48 [2] be 48 [2] 81 54 }

  condition:
    any of them
}