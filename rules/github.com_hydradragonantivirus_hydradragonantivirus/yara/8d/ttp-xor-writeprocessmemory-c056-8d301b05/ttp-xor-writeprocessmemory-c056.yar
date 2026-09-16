rule TTP_XOR_WriteProcessMemory_c056 {
  strings:
    $key_c056 = { 97 24 [2] a5 06 [2] a3 33 [2] 8d 33 [2] b2 2f }

  condition:
    any of them
}