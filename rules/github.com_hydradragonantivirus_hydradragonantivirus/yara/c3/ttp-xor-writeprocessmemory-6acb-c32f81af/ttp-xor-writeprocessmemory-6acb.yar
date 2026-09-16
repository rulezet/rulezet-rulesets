rule TTP_XOR_WriteProcessMemory_6acb {
  strings:
    $key_6acb = { 3d b9 [2] 0f 9b [2] 09 ae [2] 27 ae [2] 18 b2 }

  condition:
    any of them
}