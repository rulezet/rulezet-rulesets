rule TTP_XOR_WriteProcessMemory_6ac7 {
  strings:
    $key_6ac7 = { 3d b5 [2] 0f 97 [2] 09 a2 [2] 27 a2 [2] 18 be }

  condition:
    any of them
}