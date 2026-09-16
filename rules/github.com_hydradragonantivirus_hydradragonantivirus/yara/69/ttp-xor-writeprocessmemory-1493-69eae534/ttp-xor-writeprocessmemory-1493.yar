rule TTP_XOR_WriteProcessMemory_1493 {
  strings:
    $key_1493 = { 43 e1 [2] 71 c3 [2] 77 f6 [2] 59 f6 [2] 66 ea }

  condition:
    any of them
}