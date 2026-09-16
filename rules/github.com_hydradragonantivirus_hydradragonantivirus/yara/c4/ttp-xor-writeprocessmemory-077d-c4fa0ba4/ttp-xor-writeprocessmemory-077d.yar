rule TTP_XOR_WriteProcessMemory_077d {
  strings:
    $key_077d = { 50 0f [2] 62 2d [2] 64 18 [2] 4a 18 [2] 75 04 }

  condition:
    any of them
}