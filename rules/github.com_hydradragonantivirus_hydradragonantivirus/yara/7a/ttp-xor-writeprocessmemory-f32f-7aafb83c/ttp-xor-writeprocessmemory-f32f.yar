rule TTP_XOR_WriteProcessMemory_f32f {
  strings:
    $key_f32f = { a4 5d [2] 96 7f [2] 90 4a [2] be 4a [2] 81 56 }

  condition:
    any of them
}