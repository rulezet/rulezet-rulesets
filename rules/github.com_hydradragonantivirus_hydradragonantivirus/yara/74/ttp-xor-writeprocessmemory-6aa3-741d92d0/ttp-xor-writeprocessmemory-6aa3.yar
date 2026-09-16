rule TTP_XOR_WriteProcessMemory_6aa3 {
  strings:
    $key_6aa3 = { 3d d1 [2] 0f f3 [2] 09 c6 [2] 27 c6 [2] 18 da }

  condition:
    any of them
}