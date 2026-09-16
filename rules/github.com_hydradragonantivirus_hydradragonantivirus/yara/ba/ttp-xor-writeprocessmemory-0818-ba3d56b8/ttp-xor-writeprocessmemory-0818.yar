rule TTP_XOR_WriteProcessMemory_0818 {
  strings:
    $key_0818 = { 5f 6a [2] 6d 48 [2] 6b 7d [2] 45 7d [2] 7a 61 }

  condition:
    any of them
}