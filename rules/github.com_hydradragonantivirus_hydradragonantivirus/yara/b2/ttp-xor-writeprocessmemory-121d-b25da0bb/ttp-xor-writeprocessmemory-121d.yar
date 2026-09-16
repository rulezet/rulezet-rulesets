rule TTP_XOR_WriteProcessMemory_121d {
  strings:
    $key_121d = { 45 6f [2] 77 4d [2] 71 78 [2] 5f 78 [2] 60 64 }

  condition:
    any of them
}