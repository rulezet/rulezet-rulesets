rule TTP_XOR_WriteProcessMemory_ffb8 {
  strings:
    $key_ffb8 = { a8 ca [2] 9a e8 [2] 9c dd [2] b2 dd [2] 8d c1 }

  condition:
    any of them
}