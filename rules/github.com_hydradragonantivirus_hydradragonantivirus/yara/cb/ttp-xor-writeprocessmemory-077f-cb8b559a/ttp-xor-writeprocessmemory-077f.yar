rule TTP_XOR_WriteProcessMemory_077f {
  strings:
    $key_077f = { 50 0d [2] 62 2f [2] 64 1a [2] 4a 1a [2] 75 06 }

  condition:
    any of them
}