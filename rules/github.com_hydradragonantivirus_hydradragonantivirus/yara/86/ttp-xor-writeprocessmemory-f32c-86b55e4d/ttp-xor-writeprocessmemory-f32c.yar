rule TTP_XOR_WriteProcessMemory_f32c {
  strings:
    $key_f32c = { a4 5e [2] 96 7c [2] 90 49 [2] be 49 [2] 81 55 }

  condition:
    any of them
}