rule TTP_XOR_WriteProcessMemory_f32a {
  strings:
    $key_f32a = { a4 58 [2] 96 7a [2] 90 4f [2] be 4f [2] 81 53 }

  condition:
    any of them
}