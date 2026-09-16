rule TTP_XOR_WriteProcessMemory_efd3 {
  strings:
    $key_efd3 = { b8 a1 [2] 8a 83 [2] 8c b6 [2] a2 b6 [2] 9d aa }

  condition:
    any of them
}