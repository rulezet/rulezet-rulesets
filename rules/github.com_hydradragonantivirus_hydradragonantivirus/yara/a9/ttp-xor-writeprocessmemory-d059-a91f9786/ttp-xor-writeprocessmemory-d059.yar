rule TTP_XOR_WriteProcessMemory_d059 {
  strings:
    $key_d059 = { 87 2b [2] b5 09 [2] b3 3c [2] 9d 3c [2] a2 20 }

  condition:
    any of them
}