rule TTP_XOR_WriteProcessMemory_289d {
  strings:
    $key_289d = { 7f ef [2] 4d cd [2] 4b f8 [2] 65 f8 [2] 5a e4 }

  condition:
    any of them
}