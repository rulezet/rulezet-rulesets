rule TTP_XOR_WriteProcessMemory_03dc {
  strings:
    $key_03dc = { 54 ae [2] 66 8c [2] 60 b9 [2] 4e b9 [2] 71 a5 }

  condition:
    any of them
}